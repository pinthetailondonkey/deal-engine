import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, encodeParts, concatBytes, H } from './canonical.js';

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
// reports, and hardened after attack round two): the key a holder uses for
// one phone is a function of their master secret AND that item's id. The
// secret goes INSIDE the hash, so the child key is Hash-to-curve, not an
// affine offset: no public relation item_pub = master_pub + skew*G exists,
// two item secrets of one holder share no public constant, and a leaked
// item secret alone recovers nothing about the master.
export function deriveItemKey(masterSecretKey, itemId) {
  const master = asBytes(masterSecretKey);
  const idBytes = new TextEncoder().encode(String(itemId));
  let counter = 0;
  for (;;) {
    const digest = H(ITEM_KEY_TAG, master, idBytes, new Uint8Array([counter & 255, counter >> 8]));
    const candidate = bytesToBigInt(digest) % SECP256K1_ORDER;
    if (candidate >= 2n) {
      const priv = bigIntToBytes(candidate);
      return { secretKey: priv, publicKey: bytesToHex(schnorr.getPublicKey(priv)) };
    }
    counter += 1;
  }
}

const ITEM_KEY_TAG = 'Deal item key v2';

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
