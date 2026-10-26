import { canonicalBytes, bytesToHex, H } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';

// Key rotation and revocation. What the reports established this must be:
//
// - Rotation of a LIVE key: dual-signed (both old and new sign the same
//   body), so one key alone cannot hand authority away. It stops silent
//   rotation. It cannot stop a THIEF who holds a live key — no crypto can;
//   that is what revocation is for.
// - Revocation: a key retires ONLY itself (the signature IS the proof of
//   intent). After revocation, nothing produced by the key counts — but
//   everything produced before revocation keeps counting.
// - The observers resolve keys through a TIMELINE, so checkpoints and
//   statements are scored against the key state at their own issue time,
//   not at the moment of reading. A checkpoint signed while the key was
//   live stays genuine forever; forgeries produced with a later-stolen key
//   are visibly produced after revocation.
// - Fork evidence produced entirely by a revoked key is suspect, not a
//   verdict — standing refuses to call it FORKED. That rule is the libel
//   defense: permanent accusations must not come from a stolen key.
//
// Two honest limits, stated here because this module is where they live:
//
// - BACKDATING WINDOW. Timestamps are self-claimed — a signed body carries
//   whatever `at` its signer wrote. A thief who stole a live key can forge
//   checkpoints dated BEFORE the revocation: `keyTimelineResolve` scores a
//   body at its own claimed time, so a forged body claiming an earlier
//   moment reads `valid`. What bounds the damage is only the revocation
//   tick itself: the forged window is (last honest checkpoint, revocation
//   time). Nothing in the engine closes this — closing it needs timestamps
//   from outside the key holder (witness co-timing, an anchor, a chain).
//   Callers presenting standing should say the revocation time is exact
//   but the boundary between honest and forged history is the signer's
//   word.
// - ROTATION-TICK FALSE ALARM. `keyTimelineResolve` uses `time >= until.at`
//   on purpose: at the exact millisecond of a rotation or revocation the
//   old key is already dead, and a body claiming that exact time is refused.
//   An HONEST signer whose clock fires a checkpoint at exactly the tick
//   also gets refused — a rare, visible false alarm, chosen over the
//   alternative (`>`) which would give a thief the same millisecond. The
//   refusal reason ('retired'/'revoked') names the tick, so an honest
//   signer re-issuing one millisecond later is clean.

export const ROTATION_TAG = 'Deal rotation v1';
export const REVOCATION_TAG = 'Deal revocation v1';
export const ROLES = ['vendor', 'witness'];

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The record needs a time.');
  return value;
}

export function signRotation(oldSecretKey, newSecretKey, role, at) {
  if (!ROLES.includes(role)) throw new Error('A rotation needs a known role.');
  const oldPub = publicKeyOf(oldSecretKey);
  const newPub = publicKeyOf(newSecretKey);
  if (oldPub === newPub) throw new Error('A key cannot rotate to itself.');
  const body = {
    v: 1,
    role,
    oldKey: oldPub,
    newKey: newPub,
    at: requireAt(at),
  };
  const message = canonicalBytes(body);
  return {
    v: 1,
    tag: ROTATION_TAG,
    hash: bytesToHex(H(ROTATION_TAG, canonicalBytes(body))),
    body,
    sigs: {
      [oldPub]: sign(oldSecretKey, message),
      [newPub]: sign(newSecretKey, message),
    },
  };
}

export function rotationIsDualSigned(rotation) {
  try {
    if (!rotation?.body || rotation.tag !== ROTATION_TAG) return false;
    const message = canonicalBytes(rotation.body);
    return verify(rotation.sigs?.[rotation.body.oldKey], message, rotation.body.oldKey)
      && verify(rotation.sigs?.[rotation.body.newKey], message, rotation.body.newKey);
  } catch {
    return false;
  }
}

export function verifyRotation(rotation) {
  try {
    if (!rotation?.body || rotation.tag !== ROTATION_TAG) return false;
    if (!ROLES.includes(rotation.body.role)) return false;
    if (rotation.body.oldKey === rotation.body.newKey) return false;
    requireAt(rotation.body.at);
    if (bytesToHex(H(ROTATION_TAG, canonicalBytes(rotation.body))) !== rotation.hash) return false;
    return rotationIsDualSigned(rotation);
  } catch {
    return false;
  }
}

export function signRevocation(secretKey, role, at, foreignKey = null) {
  if (!ROLES.includes(role)) throw new Error('A revocation needs a known role.');
  const pub = publicKeyOf(secretKey);
  if (foreignKey && foreignKey !== pub) {
    throw new Error('A key can retire itself only.');
  }
  const body = { v: 1, role, key: pub, at: requireAt(at) };
  return {
    v: 1,
    tag: REVOCATION_TAG,
    hash: bytesToHex(H(REVOCATION_TAG, canonicalBytes(body))),
    body,
    sig: sign(secretKey, canonicalBytes(body)),
  };
}

export function verifyRevocation(revocation) {
  try {
    if (!revocation?.body || revocation.tag !== REVOCATION_TAG) return false;
    if (!ROLES.includes(revocation.body.role)) return false;
    requireAt(revocation.body.at);
    if (bytesToHex(H(REVOCATION_TAG, canonicalBytes(revocation.body))) !== revocation.hash) return false;
    return verify(revocation.sig, canonicalBytes(revocation.body), revocation.body.key);
  } catch {
    return false;
  }
}

// The observer-side resolution: given the timeline (entries as the core of
// each key's life) and a public key and a moment in time — was that key a
// valid one of its role at that moment?
//
// entry: { kind: 'vendor'|'witness', publicKey, from, until }
//   until: null                      — the key never left
//          { kind: 'rotated', at }   — it retired at a signed rotation
//          { kind: 'revoked', at }   — it was retired by itself
export function keyTimelineResolve(timeline, publicKey, time) {
  const entries = (timeline || []).filter((e) => e && e.publicKey === publicKey);
  if (entries.length === 0) return { valid: false, reason: 'unknown' };
  // one key appears once in an honest timeline. A duplicate is itself an
  // accusation: appending an {until: null} entry after a revocation used to
  // resurrect the key (attack round two, protocol F3) — so duplicates resolve
  // to nothing instead of "last one wins".
  if (entries.length > 1) return { valid: false, reason: 'duplicated' };
  const entry = entries[0];
  if (time < entry.from) return { valid: false, reason: 'not yet' };
  if (!entry.until) return { valid: true, role: entry.kind };
  if (time >= entry.until.at) {
    return { valid: false, reason: entry.until.kind === 'revoked' ? 'revoked' : 'retired' };
  }
  return { valid: true, role: entry.kind };
}

// Fork-evidence gate for standing.js: an evidence object counts only if
// BOTH its checkpoints were signed by keys that were valid VENDOR keys at
// their own issue time (role-blind admissions used to let a foreign key
// listed on the timeline witness checkpoints — attack round two, F3.2).
// Returns 'genuine' | 'suspect'.
export function forkEvidenceGrade(evidence, timeline) {
  if (!evidence?.a || !evidence?.b) return 'suspect';
  for (const side of [evidence.a, evidence.b]) {
    const at = side?.body?.issuedAt;
    const key = side?.key;
    if (!Number.isInteger(at) || !key) return 'suspect';
    const resolved = keyTimelineResolve(timeline, key, at);
    if (!resolved.valid || resolved.role !== 'vendor') return 'suspect';
  }
  return 'genuine';
}
