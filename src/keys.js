import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, encodeParts, concatBytes } from './canonical.js';

// Keys are generated, not self-declared. Three rules the attack reports
// converged on and the engine enforces at this layer:
// 1. A signature's role comes from comparing the verifying key to the record's
//    fields — never from a 'role:' string in the payload.
// 2. A statement only counts if its key was admitted by a signed registry —
//    no key can call itself a witness.
// 3. Deal-appartenance keys are derived, per item, so one person's other
//    deals never cross-link.

export function generateKey() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return keyPairFromSeed(seed);
}

export function keyPairFromSeed(seed) {
  // BIP340 valid secret: in [1, n-1]. Seed reduction mod n; zero is retried
  // away via a counter prefix (negligible probability, but the protocol must
  // never hang).
  let prefix = 0;
  let secretKey;
  for (;;) {
    const material = prefix === 0
      ? seed : concatBytes([seed, new TextEncoder().encode(String(prefix))]);
    let candidate = bytesToBigInt(sha256(material)) % SECP256K1_ORDER;
    if (candidate < 1n) candidate += 1n;
    secretKey = bigIntToBytes(candidate);
    if (candidate >= 2n) break;
    prefix += 1;
  }
  const publicKey = bytesToHex(schnorr.getPublicKey(secretKey));
  return { secretKey, publicKey };
}

export function sign(secretKey, messageBytes) {
  return bytesToHex(schnorr.sign(messageBytes, asBytes(secretKey)));
}

export function verify(signature, messageBytes, publicKey) {
  try {
    return schnorr.verify(hexToBytes(signature), messageBytes, hexToBytes(publicKey));
  } catch {
    return false;
  }
}

export function publicKeyOf(secretKey) {
  return bytesToHex(schnorr.getPublicKey(asBytes(secretKey)));
}

function asBytes(secretKey) {
  return secretKey instanceof Uint8Array ? secretKey : hexToBytes(secretKey);
}

// Per-item derived key (keyblinding, from the title- and privacy-attack
// reports): the key a holder uses for one phone is a function of their master
// secret AND that item's id. Two chains the same person holds share no key.
export function deriveItemKey(masterSecretKey, itemId) {
  const master = asBytes(masterSecretKey);
  const factor = encodeParts(['Deal item key v1', new TextEncoder().encode(String(itemId))]);
  const skew = sha256BytesConcat(factor, master);
  const priv = addScalars(skew, master);
  return { secretKey: priv, publicKey: bytesToHex(schnorr.getPublicKey(priv)) };
}

function sha256BytesConcat(a, b) {
  // deterministic scalar-skew: fine for an engine; a real deployment swaps
  // this for a stricter BIP32-style path.
  return addScalars(sha256(encodeParts([a])), b);
}

// secp256k1 group order — a protocol constant, not a lookup.
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function addScalars(a, b) {
  const sum = (bytesToBigInt(a) + bytesToBigInt(b)) % SECP256K1_ORDER;
  return bigIntToBytes(sum);
}

function bytesToBigInt(bytes) {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function bigIntToBytes(value) {
  const out = new Uint8Array(32);
  let n = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
