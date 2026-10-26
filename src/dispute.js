import { canonicalBytes, bytesToHex, H } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';

// Disputes: filed by one party, resolved by a co-signed record. The title-
// and incentive-attack reports agreed this is existential: a dispute with no
// resolution path is a permanent defamation primitive. The engine forces a
// resolution record type and treats RESOLVED as its own states, not silence.

export const DISPUTE_TAG = 'Deal dispute v1';
export const RESOLUTION_TAG = 'Deal resolution v1';
export const VERDICTS = ['settled', 'withdrawn', 'overturned'];

export function disputeBody(input = {}) {
  return {
    v: 1,
    about: String(input.about || ''), // hash of the record or hop in question
    from: String(input.from || '').toLowerCase(),
    against: String(input.against || '').toLowerCase(),
    claim: String(input.claim || ''),
    at: requireAt(input.at),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The dispute needs a time.');
  return value;
}

export function signDispute(secretKey, input) {
  const body = disputeBody(input);
  const pub = publicKeyOf(secretKey);
  if (pub !== body.from) throw new Error('Only the filer signs the dispute.');
  if (body.from === body.against) throw new Error('A dispute of oneself files nothing.');
  if (!body.claim) throw new Error('The dispute needs a written claim.');
  return {
    v: 1,
    tag: DISPUTE_TAG,
    hash: bytesToHex(H(DISPUTE_TAG, canonicalBytes(body))),
    body,
    sig: sign(secretKey, canonicalBytes(body)),
  };
}

export function verifyDispute(signed) {
  try {
    if (!signed?.body || !signed?.sig) return false;
    if (signed.tag !== DISPUTE_TAG) return false;
    const body = disputeBody(signed.body);
    if (bytesToHex(H(DISPUTE_TAG, canonicalBytes(body))) !== signed.hash) return false;
    if (body.from === body.against || !body.claim) return false;
    return verify(signed.sig, canonicalBytes(body), body.from);
  } catch {
    return false;
  }
}

// resolution: at least the two parties sign; a named arbiter may add a third
// signature. `verdict` is one of VERDICTS. Withdrawn means the filer signed
// it off personally — this is how a bad-faith dispute stops damaging anyone.
export function signResolution(secretKeys, signedDispute, verdict, at, contextKeys = {}) {
  if (!verifyDispute(signedDispute)) throw new Error('A resolution resolves a valid dispute.');
  if (!VERDICTS.includes(verdict)) throw new Error('Not a known verdict.');
  const body = {
    v: 1,
    resolves: signedDispute.hash,
    verdict,
    at: requireAt(at),
  };
  const sigs = {};
  for (const secretKey of [].concat(secretKeys)) {
    sigs[publicKeyOf(secretKey)] = sign(secretKey, canonicalBytes(body));
  }
  if (verdict === 'withdrawn' && !sigs[signedDispute.body.from]) {
    throw new Error('Only the filer can withdraw the claim.');
  }
  return {
    v: 1,
    tag: RESOLUTION_TAG,
    resolves: signedDispute.hash,
    body,
    sigs,
  };
}

export function verifyResolution(signedDispute, resolution, arbiterKeys = []) {
  try {
    if (!resolution?.body || resolution.tag !== RESOLUTION_TAG) return false;
    if (resolution.body.resolves !== signedDispute?.hash) return false;
    if (!VERDICTS.includes(resolution.body.verdict)) return false;
    if (!verifyDispute(signedDispute)) return false;
    const message = canonicalBytes(resolution.body);
    const signers = Object.entries(resolution.sigs || {});
    if (signers.length === 0) return false;
    const parties = [signedDispute.body.from, signedDispute.body.against];
    const admitted = [...parties, ...arbiterKeys.map((key) => String(key).toLowerCase())];
    let covered = 0;
    for (const [key, sig] of signers) {
      if (!admitted.includes(key)) return false; // no unknown cosigners
      if (!verify(sig, message, key)) return false;
      if (parties.includes(key)) covered += 1;
    }
    if (resolution.body.verdict === 'withdrawn') {
      return !!resolution.sigs[signedDispute.body.from];
    }
    return covered === 2 || Object.keys(resolution.sigs).length >= 2;
  } catch {
    return false;
  }
}

// A dispute renders as: unresolved ('open', the ⚠ headline), or resolved with
// its verdict. Resolved disputes keep their history; they stop screaming.
export function disputeStatus(signedDispute, resolutions = []) {
  const valid = resolutions.filter((entry) => {
    try {
      return verifyResolution(signedDispute, entry);
    } catch {
      return false;
    }
  });
  if (valid.length === 0) return { state: 'open', verdict: '' };
  return { state: 'resolved', verdict: valid[valid.length - 1].body.verdict };
}
