import { canonicalBytes, bytesToHex, H, hashHex } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';
import { rotationIsDualSigned } from './rotation.js';

// Signed Tree Checkpoint (STC). Fix for four attacker findings in one object:
// - every field — seq, size, root, previous head hash, key id — sits inside
//   the signature. Continuity is computed (`extends prior` becomes true or
//   false after a check), not claimed.
// - cadence is NOT a checkpoint field. It is a protocol constant, so a vendor
//   cannot ratchet freshness to once-a-year.
// - the checkpoint carries a signed witness registry. A witness statement
//   only counts if its key is admitted there — no self-declared witnesses.
// - witnesses sign statement bytes that bind the checkpoint's canonical
//   bytes: the same checkpoint shown to two witnesses cannot differ.

export const STC_TAG = 'Deal checkpoint v1';
export const WITNESS_TAG = 'Deal witness v1';
export const FORK_TAG = 'Deal fork evidence v1';
export const REFUSAL_TAG = 'Deal refusal v1';

// protocol constant. freshedness is not vendor-scheduled.
export const CADENCE_MS = 7 * 24 * 60 * 60 * 1000;

// Field shapes (attack round two, finding 3): a checkpoint whose root is ''
// commits to nothing, and an accRoot of '01' (the integer 1) is the
// multiplicative identity — any witness rides in. The head hash binds these
// canonical bytes either way, so the shapes are enforced here, at the only
// door a body can enter through.
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_EVEN = /^([0-9a-f]{2})+$/;

export function checkpointBody(input = {}) {
  const body = {
    v: 1,
    seq: requireInt(input.seq, 'seq'),
    treeSize: requireInt(input.treeSize, 'treeSize'),
    root: String(input.root || '').toLowerCase(),
    prevHead: String(input.prevHead || '').toLowerCase(),
    issuedAt: requireInt(input.issuedAt, 'issuedAt'),
    keyId: String(input.keyId || ''),
    witnessRegistry: witnessRegistryCanonical(input.witnessRegistry),
    // the position-blind accumulator, optional: empty when not opted in
    accN: String(input.accN || '').toLowerCase(),
    accRoot: String(input.accRoot || '').toLowerCase(),
  };
  if (!body.keyId) throw new Error('The checkpoint needs a key id.');
  if (!HEX64.test(body.root)) throw new Error('The checkpoint root is a 64-hex digest.');
  if (body.prevHead !== '' && !HEX64.test(body.prevHead)) {
    throw new Error('The prior head is a 64-hex digest, or empty at genesis.');
  }
  if (body.accN !== '' && !HEX_EVEN.test(body.accN)) throw new Error('The accumulator modulus is hex bytes.');
  if (body.accRoot !== '' && !(body.accRoot.length >= 64 && HEX_EVEN.test(body.accRoot))) {
    throw new Error('The accumulator root is hex bytes of digest width or more.');
  }
  return body;
}

function requireInt(value, name) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`The checkpoint needs a ${name}.`);
  return value;
}

// The registry canonicalizes two ways on purpose: raw callers hand a list,
// but a body read back from a signed checkpoint carries the pipe-joined
// string — verifyCheckpoint re-derives the body through here, so both forms
// must land on the same sorted string or the head hash breaks.
function witnessRegistryCanonical(value) {
  const list = Array.isArray(value)
    ? value
    : (typeof value === 'string' ? value.split('|') : []);
  return [...new Set(list.filter(Boolean).map((key) => String(key).toLowerCase()))].sort().join('|');
}

export function checkpointHash(body) {
  return bytesToHex(H(STC_TAG, canonicalBytes(body)));
}

export function checkpointMessageBytes(body) {
  return canonicalBytes(body);
}

export function signCheckpoint(secretKey, body) {
  const canonicalBody = checkpointBody(body);
  const pub = publicKeyOf(secretKey);
  if (canonicalBody.keyId !== keyIdOf(pub)) {
    throw new Error('The checkpoint key does not match its key id.');
  }
  return {
    v: 1,
    tag: STC_TAG,
    head: checkpointHash(canonicalBody),
    body: canonicalBody,
    key: pub,
    sig: sign(secretKey, checkpointMessageBytes(canonicalBody)),
  };
}

export function keyIdOf(publicKey) {
  return hashHex('Deal key id v1', publicKey).slice(0, 16);
}

export function verifyCheckpoint(signed) {
  try {
    if (!signed?.body || !signed?.sig) return false;
    if (signed.tag !== STC_TAG) return false;
    if (!signed.key) return false;
    const body = checkpointBody(signed.body);
    if (bytesToHex(H(STC_TAG, canonicalBytes(body))) !== signed.head) return false;
    if (keyIdOf(signed.key) !== body.keyId) return false;
    return verify(signed.sig, checkpointMessageBytes(body), signed.key);
  } catch {
    return false;
  }
}

// Witness statements: content-bound, registry-gated, chain-linked.
// body: { stc head hash, witnessTime, prevHead (the previous STC this witness
// signed on this line) }
export function signWitnessStatement(witnessSecret, stc, priorStatement = null) {
  if (!verifyCheckpoint(stc)) throw new Error('Witness signs a valid checkpoint only.');
  const registry = stc.body.witnessRegistry.split('|').filter(Boolean);
  const witnessPub = publicKeyOf(witnessSecret);
  if (!registry.includes(witnessPub)) {
    throw new Error('That key is not in this checkpoint\'s witness registry.');
  }
  const body = {
    v: 1,
    stcHead: stc.head,
    witnessTime: Number(stc.body.issuedAt),
    prevStcHead: priorStatement ? String(priorStatement.body?.stcHead || '') : '',
  };
  return {
    v: 1,
    tag: WITNESS_TAG,
    witness: witnessPub,
    body,
    sig: sign(witnessSecret, canonicalBytes(body)),
  };
}

export function verifyWitnessStatement(stc, statement, rotations = []) {
  try {
    if (!statement?.body || !statement?.sig) return false;
    if (statement.tag !== WITNESS_TAG) return false;
    if (!verifyCheckpoint(stc)) return false;
    if (statement.body.stcHead !== stc.head) return false;
    const registry = stc.body.witnessRegistry.split('|').filter(Boolean);
    // admission: direct registry membership, or a dual-signed rotation on
    // record reaching back to a key the registry admitted. Never self-claim.
    if (!registry.includes(statement.witness)
      && !admittedWitness(stc, statement.witness, rotations)) return false;
    if (Number(stc.body.issuedAt) !== Number(statement.body.witnessTime)) return false;
    return verify(statement.sig, canonicalBytes(statement.body), statement.witness);
  } catch {
    return false;
  }
}

// Witness admission, including inheritance: a rotated witness key counts
// only if a dual-signed rotation on record starts from a key the registry
// already admitted, at or before the checkpoint's issue time. No key
// admits itself. (Signature and head checks are done by the caller.)
export function admittedWitness(stc, witnessPub, rotations = []) {
  let registry;
  try {
    registry = stc.body.witnessRegistry.split('|').filter(Boolean);
  } catch {
    return false;
  }
  if (registry.includes(witnessPub)) return true;
  for (const rotation of rotations || []) {
    if (!rotation || rotation.body?.role !== 'witness') continue;
    // a rotation without a time predates nothing: NaN > issuedAt is false,
    // so the missing-at case used to slip through the gate (attack round
    // two, finding 8) — require a real integer `at`.
    if (!Number.isInteger(rotation.body.at)) continue;
    if (Number(rotation.body.at) > Number(stc.body.issuedAt)) continue;
    if (!registry.includes(rotation.body.oldKey)) continue;
    if (rotation.body.newKey === witnessPub) return rotationIsDualSigned(rotation);
  }
  return false;
}

// Fork evidence: any two valid checkpoints that claim the same previous head
// but disagree on root or size. Both signatures verify independently — this
// is evidence, not a verdict (the design's FORKED state). Full checkpoints
// are carried so anyone can check.
export function forkEvidence(stcA, stcB) {
  if (!verifyCheckpoint(stcA) || !verifyCheckpoint(stcB)) return null;
  if (stcA.head === stcB.head) return null;
  if (stcA.body.prevHead !== stcB.body.prevHead) return null;
  if (stcA.body.root === stcB.body.root && stcA.body.treeSize === stcB.body.treeSize) return null;
  return { v: 1, tag: FORK_TAG, a: stcA, b: stcB };
}

export function verifyForkEvidence(evidence) {
  return forkEvidence(evidence?.a, evidence?.b) != null;
}

// Vendor refusal of an audit: a signed thing that ages like staleness. Never
// an accusation — the design keeps refusal separate from guilt.
export function signRefusal(secretKey, at) {
  const body = { v: 1, key: publicKeyOf(secretKey), at: requireRefusalAt(at) };
  return {
    v: 1,
    tag: REFUSAL_TAG,
    hash: bytesToHex(H(REFUSAL_TAG, canonicalBytes(body))),
    keyId: keyIdOf(body.key),
    body,
    sig: sign(secretKey, canonicalBytes(body)),
  };
}

function requireRefusalAt(at) {
  if (!Number.isInteger(at) || at <= 0) throw new Error('The refusal needs a time.');
  return at;
}

export function verifyRefusal(refusal) {
  try {
    if (!refusal?.body || !refusal?.sig) return false;
    if (refusal.tag !== REFUSAL_TAG) return false;
    if (keyIdOf(refusal.body.key) !== refusal.keyId) return false;
    return verify(refusal.sig, canonicalBytes(refusal.body), refusal.body.key);
  } catch {
    return false;
  }
}
