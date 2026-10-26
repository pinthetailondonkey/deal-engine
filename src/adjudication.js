import { canonicalBytes, bytesToHex, H } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';
import { verifyWitnessStatement, verifyForkEvidence } from './checkpoint.js';
import { keyTimelineResolve } from './rotation.js';

// Fork adjudication — an evaluator, not a verdict machine.
//
// The design said "independently verifiable" for a forked state and the
// reports replied that two lines with disjoint witness sets are
// indistinguishable from a relay partition: no crypto trick closes that,
// only a PROCEDURE. This module is the procedure:
//
// 1. FORK-PROVED: the same admitted witness key signed both sides of the
//    split. The observer re-checks each statement's signature against its
//    witness key — statements are never trusted, only re-verified.
// 2. VENDOR-CONFIRMED: the checkpoint-signing key names (dual-recorded)
//    one line it keeps; the other is declared dead. The vendor's signature
//    over THIS evidence ends the ambiguity — the honest question (which
//    line was real) becomes unnecessary.
// 3. ADJUDICATION-OPEN: incompatible lines but no shared witness and no
//    admission. A partition is possible. The design refuses to guess, and
//    visibly — the dispute stays open until new evidence arrives.
//
// Out of scope, stated: witness-OVERLAP ECONOMICS (whether honest markets
// naturally converge on shared witnesses) is a market question, not code.

export const ADMISSION_TAG = 'Deal fork admission v1';

export function adjudicateFork(evidence, statements = [], opts = {}) {
  // Standing in the door: the input must BE fork evidence — both sides
  // verify as checkpoints, heads differ, they claim one parent. The
  // standing module grades this before calling, but adjudicateFork is
  // exported, and a direct caller passing a degenerate pair
  // ({a: stc, b: stc}) got a `fork-proved` verdict out of ONE honest
  // statement: with a side-equals-b, the same checkpoint matched both
  // sides and a single witness statement was read as signing the split.
  // Attack round three (residual): evidence is arrived at, never assumed —
  // unevidenced input grades adjudication-open, flagged in reason.
  if (!verifyForkEvidence(evidence)) {
    return { verdict: 'adjudication-open', sharedWitness: null, reason: 'unevidenced' };
  }
  if (!evidence?.a || !evidence?.b) return { verdict: 'adjudication-open', sharedWitness: null };
  // statements are re-verified through the FULL witness machinery — not just
  // the signature. A statement counts only if the machinery that admits
  // witnesses accepts it against the side it names: the tag, the stcHead
  // binding, witnessTime, and admission (registry or dual-signed rotation).
  // Attack round two showed the signature-only filter let a stranger key
  // with valid signatures over {stcHead} drive FORKED.
  const sideOf = (statement) => {
    if (statement.body.stcHead === evidence.a.head) return evidence.a;
    if (statement.body.stcHead === evidence.b.head) return evidence.b;
    return null;
  };
  const genuine = (statements || []).filter((statement) => {
    try {
      const side = sideOf(statement);
      if (!side) return false;
      return verifyWitnessStatement(side, statement, opts.witnessRotations || [], {
        keyTimeline: opts.keyTimeline || null,
      });
    } catch {
      return false;
    }
  });
  const signedA = new Set(genuine.filter((s) => s.body.stcHead === evidence.a.head).map((s) => s.witness));
  for (const statement of genuine) {
    if (statement.body.stcHead === evidence.b.head && signedA.has(statement.witness)) {
      return { verdict: 'fork-proved', sharedWitness: statement.witness };
    }
  }

  // vendor admission path: the admission must be signed by the key that
  // signed the checkpoints, name this split, and — when the view carries a
  // key timeline — the signer must STILL be a live vendor key at the
  // admission's own time (a thief holding a since-revoked key does not get
  // the final word).
  const vendorAdmission = opts?.vendorAdmission;
  if (vendorAdmission && verifyVendorAdmission(vendorAdmission)) {
    const signer = vendorAdmission.key;
    const signerLive = opts?.keyTimeline
      ? keyTimelineResolve(opts.keyTimeline, signer, vendorAdmission.body.at).valid === true
      : true;
    if (signerLive && vendorAdmission.body.keep === evidence.a.head
      && vendorAdmission.body.drop === evidence.b.head
      && signer === evidence.a.key) {
      return { verdict: 'vendor-confirmed', kept: evidence.a.head, dropped: evidence.b.head };
    }
    if (signerLive && vendorAdmission.body.keep === evidence.b.head
      && vendorAdmission.body.drop === evidence.a.head
      && signer === evidence.b.key) {
      return { verdict: 'vendor-confirmed', kept: evidence.b.head, dropped: evidence.a.head };
    }
  }
  return { verdict: 'adjudication-open', sharedWitness: null };
}

// The vendor names the line that is real. This is a signed admission, and
// it is itself evidence — not standing. It only becomes meaningful when
// held NEXT TO the fork evidence it matches (the key must be the same key
// that signed the checkpoints in the evidence, checked by adjudicateFork).
export function signVendorAdmission(vendorSecretKey, { keep, drop, at }) {
  const body = {
    v: 1,
    keep: String(keep || ''),
    drop: String(drop || ''),
    at: requireAt(at),
  };
  const key = publicKeyOf(vendorSecretKey);
  return {
    v: 1,
    tag: ADMISSION_TAG,
    hash: bytesToHex(H(ADMISSION_TAG, canonicalBytes(body))),
    body,
    key,
    sig: sign(vendorSecretKey, canonicalBytes(body)),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The admission needs a time.');
  return value;
}

export function verifyVendorAdmission(admission) {
  try {
    if (!admission?.body || admission.tag !== ADMISSION_TAG) return false;
    requireAt(admission.body.at);
    if (bytesToHex(H(ADMISSION_TAG, canonicalBytes(admission.body))) !== admission.hash) return false;
    return verify(admission.sig, canonicalBytes(admission.body), admission.key);
  } catch {
    return false;
  }
}
