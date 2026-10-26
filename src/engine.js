import { makeLog, mixedSaltHex } from './log.js';
import { bytesToHex } from './canonical.js';
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
import { generateModulus, elementOf, accRootOf, accWitness, verifyBlindMembership } from './accumulator.js';
import { standing } from './standing.js';
import { signRotation, signRevocation, keyTimelineResolve } from './rotation.js';
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
export function createEngine({ vendor, now = () => Date.now(), accSeed, accBits = 2048 } = {}) {
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
  const keyTimeline = [{ kind: 'vendor', publicKey: vendorPair.publicKey, from: 0, until: null }];
  const witnessRotations = [];

  // The accumulator (position-blind membership), opted in by engine
  // options accSeed / accBits or the first checkpoint that passes them.
  // One engine keeps one stable modulus for its whole life.
  let accMods = null;
  let accSeedOpt = accSeed ?? null;
  engine.accKey = () => {
    if (!accMods) {
      if (typeof accSeedOpt !== 'string') {
        throw new Error('The accumulator is opted in with a seed: engine.checkpoint({accSeed}).');
      }
      accMods = generateModulus({ seed: accSeedOpt, bits: accBits });
    }
    return accMods;
  };

  // Key rotation: old and new vendor keys sign one record; the engine's
  // checkpoint path switches to the new key. Honest limit, stated here:
  // dual-signing stops silent rotation. A thief holding a live key can
  // co-sign their own replacement — that is what revocation is for.
  engine.rotateVendorKey = (newSecretKey) => {
    const rotation = signRotation(engine.keys.secretKey, newSecretKey, 'vendor', now());
    const current = keyTimeline[keyTimeline.length - 1];
    current.until = { kind: 'rotated', at: rotation.body.at };
    keyTimeline.push({ kind: 'vendor', publicKey: rotation.body.newKey, from: rotation.body.at, until: null });
    engine.keys = { secretKey: newSecretKey, publicKey: rotation.body.newKey };
    engine.vendorPublic = rotation.body.newKey;
    log.setVendor(rotation.body.newKey);
    return rotation;
  };

  // A key retires itself. After the tick, nothing it produces counts — but
  // everything produced BEFORE the tick keeps its standing.
  engine.revokeVendorKey = () => {
    const revocation = signRevocation(engine.keys.secretKey, 'vendor', now());
    const current = keyTimeline[keyTimeline.length - 1];
    current.until = { kind: 'revoked', at: revocation.body.at };
    return revocation;
  };

  engine.rotateWitness = (oldSecretKey, newSecretKey, opts = {}) => {
    const rotation = signRotation(oldSecretKey, newSecretKey, 'witness', opts.at ?? now());
    witnessRotations.push(rotation);
    return rotation;
  };

  engine.keys = vendorPair;

  // Salt provenance: the vendor always brings fresh 16 bytes; the buyer MAY
  // contribute (a hex string, at least 8 bytes of entropy) and the stored
  // salt is a domain-separated mix of both. The returned provenance never
  // lies about who held the randomness.
  engine.commitDeal = (record, buyerSalt) => {
    const vendorSaltBytes = crypto.getRandomValues(new Uint8Array(16));
    let salt;
    if (buyerSalt === undefined || buyerSalt === null) {
      salt = log.commit(record, bytesToHex(vendorSaltBytes));
    } else {
      salt = log.commit(record, mixedSaltHex(vendorSaltBytes, buyerSalt));
    }
    return { salt, saltProvenance: buyerSalt === undefined || buyerSalt === null ? 'vendor' : 'vendor+buyer' };
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
  // match the latest checkpoint this engine already signed. opts.accSeed
  // opts the accumulator in: the same seed keeps one stable N across all
  // of this engine's checkpoints (dev seeds are deterministic — see
  // accumulator.js; production reads random bytes).
  engine.checkpoint = (opts = {}) => {
    const prior = stcs.filter(verifyCheckpoint).slice(-1)[0] || null;
    if (prior && opts.priorHead && opts.priorHead !== prior.head) {
      throw new Error('A checkpoint extends the latest one or nothing.');
    }
    // once the accumulator is opted in, every later checkpoint keeps
    // publishing it — a dormant engine stays field-free instead.
    let accN = '';
    if (opts.accSeed !== undefined || accMods) {
      if (opts.accSeed !== undefined) accSeedOpt = opts.accSeed;
      accN = engine.accKey().n.toString(16);
    }
    const stc = log.signedTreeState(engine.keys.secretKey, {
      seq: opts.seq ?? ((prior?.body.seq ?? 0) + 1),
      issuedAt: opts.at ?? now(),
      witnessRegistry: opts.witnessRegistry || [],
      priorHead: prior?.head || '',
      accN,
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
    // the same key-timeline gate standing applies, applied here so every
    // public surface (count, size history) grades keys identically
    const gated = stcs.filter((entry) => verifyCheckpoint(entry)
      && keyTimelineResolve(keyTimeline, entry.key, entry.body.issuedAt).valid);
    const checkpoints = gated;
    const stc = checkpoints.slice(-1)[0] || null;
    const statements = stc
      ? ([...witnesses.values()].filter(
        (s) => verifyParamsWitness(s, stc),
      )) : [];
    const st = standing({
      checkpoints,
      witnessStatements: statements,
      forkEvidence: forkEvidenceList,
      refusals,
      sizeHistory: checkpoints.map((c) => ({ at: c.body.issuedAt, size: c.body.treeSize, seq: c.body.seq })),
      keyTimeline,
      witnessRotations,
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

  // The blind window: the SAME membership, proven without position and
  // without size. Returns the element root/witness pair from the newest
  // accumulator checkpoint and nothing else — no index, no treeSize, no
  // co-path to triangulate from. The honesty gates read like the rest of
  // the engine: a record the newest checkpoint never counted is refused
  // membership, and the published root is cross-checked against the live
  // log before any witness leaves the house.
  engine.revealDealBlind = (dealId) => {
    const index = log.records.findIndex((row) => row.record.body.dealId === dealId);
    if (index < 0) return { granted: false, reason: 'not in log' };
    const stc = stcs.filter(verifyCheckpoint).slice(-1)[0] || null;
    if (!stc || !stc.body || !stc.body.accN || !stc.body.accRoot) {
      return { granted: false, reason: 'no published accumulator' };
    }
    if (index >= stc.body.treeSize) {
      return { granted: false, reason: 'not in the newest checkpoint' };
    }
    const slice = log.records.slice(0, stc.body.treeSize);
    const elements = slice.map((_, i) => elementOf(bytesToHex(log.leafBytes(i))));
    const root = accRootOf(elements, stc.body.accN);
    if (root !== stc.body.accRoot) {
      return { granted: false, reason: 'the log does not match its own checkpoint' };
    }
    const witness = accWitness(elements, index, stc.body.accN);
    const answer = {
      granted: true,
      root: stc.body.accRoot,
      n: stc.body.accN,
      elem: elements[index],
      witness,
    };
    // the answer proves itself the same way an auditor would check it
    if (!verifyBlindMembership(answer, answer.elem, answer.witness)) {
      return { granted: false, reason: 'the witness did not verify' };
    }
    return answer;
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
