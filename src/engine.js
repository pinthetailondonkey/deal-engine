import { makeLog } from './log.js';
import { makeTree, verifyInclusionProof } from './merkle.js';
import {
  verifyCheckpoint,
  signWitnessStatement, verifyWitnessStatement,
  forkEvidence, verifyForkEvidence, signRefusal, verifyRefusal,
} from './checkpoint.js';
import { signRecord, verifyRecord, signVoid, verifyVoid } from './record.js';
import {
  signDispute, signResolution, disputeStatus,
} from './dispute.js';
import { generateKey, sign, verify, publicKeyOf } from './keys.js';
import { standing } from './standing.js';
import { amountUnits, unitsToAmount, normalizeAmount, sumAmounts } from './units.js';
import {
  itemKeyPair, signHop, verifyHopChain, truncateTitleLineage,
} from './title.js';

// DealEngine — the facade. One vendor's log, seen by one observer, plus the
// title surface. Everything the CLI tests exercise lives here; nothing here
// touches a relay, a wallet, or a UI.
//
// Observer's rules, learned from the attack reports:
// - a count is reported as "witnessed deals in the latest checkpoint",
//   with its size history. Never as "deals completed".
// - a reveal without an authorized window cannot be computed. The engine
//   hands out inclusion proofs only with the leaf's salt — no salt, no
//   membership oracle. (Rule 10: correlation is a read.)
// - disclosure answers are separately priced: one reveal answers one leaf.
export function createEngine({ vendor, now = () => Date.now() } = {}) {
  const vendorPair = generateKey();
  const engine = {
    vendor,
    vendorPublic: vendorPair.publicKey,
    standingClock: now,
  };

  const log = makeLog({ vendorKey: engine.vendorPublic });
  const witnesses = new Map(); // witness pubkey -> their previous statement
  const stcs = [];         // checkpoints, in arrival order
  const forkEvidenceList = [];
  const refusals = [];
  const titles = new Map();       // itemKey -> { hops: [] }
  const disputeBook = new Map();  // dispute hash -> { dispute, resolutions: [] }

  engine.keys = vendorPair;

  engine.commitDeal = (record, saltOverride) => {
    const salt = log.commit(record, saltOverride);
    return { salt };
  };

  // A refund or undo: a signed entry on a ledger BESIDE the count. The count
  // never decrements; the void never deletes.
  engine.voidDeal = (dealId, partySecretKey, reason) => {
    const row = log.records.find((entry) => entry.record.body.dealId === dealId);
    if (!row) throw new Error('That deal is not in the log.');
    const voided = signVoid(partySecretKey, row.record, reason, now());
    log.void(row.record, voided);
    return voided;
  };

  engine.countersign = (record) => signRecord(engine.keys.secretKey, record.body, record);

  // The checkpoint the vendor publishes. seq must increase; prevHead must
  // match the latest checkpoint this engine already signed.
  engine.checkpoint = (opts = {}) => {
    const prior = stcs.filter(verifyCheckpoint).slice(-1)[0] || null;
    if (prior && opts.priorHead && opts.priorHead !== prior.head) {
      throw new Error('A checkpoint extends the latest one or nothing.');
    }
    const stc = log.signedTreeState(engine.keys.secretKey, {
      seq: opts.seq ?? ((prior?.body.seq ?? 0) + 1),
      issuedAt: opts.at ?? now(),
      witnessRegistry: opts.witnessRegistry || [],
      priorHead: prior?.head || '',
    });
    stcs.push(stc);
    return stc;
  };

  // A witness with an admitted key signs the checkpoint's bytes. Each
  // witness's statement chain-links to their previous one, so a fork by the
  // same key pair is provable, not just deniable.
  engine.witness = (witnessSecret) => {
    const stc = latestWitnessable();
    const witnessPub = publicKeyOf(witnessSecret);
    const statement = signWitnessStatement(witnessSecret, stc, witnesses.get(witnessPub) || null);
    witnesses.set(witnessPub, statement);
    return statement;
  };

  engine.checkFork = (stcA, stcB) => {
    const evidence = forkEvidence(stcA, stcB);
    if (evidence) forkEvidenceList.push(evidence);
    return evidence;
  };

  engine.refuseAudit = (opts = {}) => {
    const refusal = signRefusal(engine.keys.secretKey, opts.at ?? now());
    refusals.push(refusal);
    return refusal;
  };

  // ---- disputes -----------------------------------------------------------

  // Filed by one party about a record hash or hop hash. RESOLVED requires a
  // co-signed record; nothing in the engine let a dispute stay `open` while
  // a valid resolution exists beside it.
  engine.fileDispute = (secretKey, input) => {
    const dispute = signDispute(secretKey, input);
    disputeBook.set(dispute.hash, { dispute, resolutions: [] });
    return dispute;
  };

  engine.resolveDispute = (secretKeys, dispute, verdict, opts = {}) => {
    if (verdict === 'withdrawn' && opts.arbiterKeys?.length) {
      throw new Error('A withdrawal has no arbiter.');
    }
    const resolution = signResolution([].concat(secretKeys), dispute, verdict, opts.at ?? now(), {
      arbiterKeys: opts.arbiterKeys || [],
    });
    const entry = disputeBook.get(dispute.hash);
    if (!entry) throw new Error('That dispute is not filed here.');
    entry.resolutions.push(resolution);
    return resolution;
  };

  engine.disputeStatus = (dispute) => {
    const entry = disputeBook.get(dispute.hash);
    const resolutions = entry ? entry.resolutions : [];
    return disputeStatus(dispute, resolutions);
  };

  // ---- queries ------------------------------------------------------------

  engine.publicState = (opts = {}) => {
    const nowAt = opts.now ?? now();
    const checkpoints = stcs.filter(verifyCheckpoint);
    const stc = checkpoints.slice(-1)[0] || null;
    const statements = stc
      ? (stcs.filter(verifyCheckpoint), [...witnesses.values()].filter(
        (s) => verifyParamsWitness(s, stc),
      )) : [];
    const st = standing({
      checkpoints,
      witnessStatements: statements,
      forkEvidence: forkEvidenceList,
      refusals,
      sizeHistory: checkpoints.map((c) => ({ at: c.body.issuedAt, size: c.body.treeSize, seq: c.body.seq })),
      voided: log.voided,
    }, nowAt);
    return {
      // worded exactly as the design's honest downgrade asks:
      countLabel: 'witnessed deals in the latest checkpoint',
      count: stc ? stc.body.treeSize : 0,
      sizeHistory: st.details.sizeHistory,
      rootAt: stc ? stc.body.root : '',
      standing: st,
    };
  };

  function verifyParamsWitness(statement, stc) {
    try {
      return verifyWitnessStatement(stc, statement);
    } catch {
      return false;
    }
  }

  // One leaf's audit window: leaf bytes, salt, inclusion proof. Without the
  // salt — which only opens when both parties authorize — an auditor gets
  // a refusal object, never a membership oracle.
  engine.revealDeal = (dealId) => {
    const index = log.records.findIndex((row) => row.record.body.dealId === dealId);
    if (index < 0) return { granted: false, reason: 'not in log' };
    const tree = makeTree(log.records.map((_, i) => log.leafBytes(i)));
    const leafBytes = log.leafBytes(index);
    const proof = tree.inclusionProof(index);
    return {
      granted: true,
      leafBytes: toHex(leafBytes),
      proof: proof.map(toHex),
      treeSize: log.records.length,
      root: toHex(tree.mthAll()),
      check: verifyInclusionProof(leafBytes, index, log.records.length, proof, toHex(tree.mthAll())),
    };
  };

  // ---- money --------------------------------------------------------------

  engine.money = {
    units: amountUnits,
    display: unitsToAmount,
    normalize: normalizeAmount,
    sum: sumAmounts,
  };

  // ---- title --------------------------------------------------------------

  engine.title = {
    itemKey: (itemId) => itemKeyPair(engine.keys.secretKey, itemId),
    signHop: (secretKeys, body) => signHop(secretKeys, body),
    verifyChain: verifyHopChain,
    truncate: (thatItemKeyPub) => {
      const prior = (titles.get(thatItemKeyPub)?.hops || []).slice(-1)[0] || null;
      const hop = truncateTitleLineage(engine.keys.secretKey, prior, thatItemKeyPub, now());
      addHop(thatItemKeyPub, hop);
      return hop;
    },
  };

  function addHop(itemKeyPub, hop) {
    if (!titles.has(itemKeyPub)) titles.set(itemKeyPub, { hops: [] });
    titles.get(itemKeyPub).hops.push(hop);
  }

  function latestWitnessable() {
    const valid = stcs.filter(verifyCheckpoint);
    if (valid.length === 0) throw new Error('Nothing to witness yet.');
    return valid[valid.length - 1];
  }

  function toHex(bytes) {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
  }

  return engine;
}

export const ENGINE_CHECKS = {
  verifyCheckpoint,
  verifyRecord,
  verifyWitnessStatement,
  verifyForkEvidence,
  verifyRefusal,
  amountUnits,
};
