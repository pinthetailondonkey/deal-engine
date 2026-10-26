import { bytesToHex, hexToBytes, H } from './canonical.js';

// The position-blind membership surface.
//
// A Merkle inclusion proof proves membership but also hands over the
// leaf's position and the tree's size — correlation is a read, and the
// reports said a revealed window leaks more than it answers. An
// accumulator fixes that: one integer (the root) commits to the whole
// set without saying how many things are in it, and a membership
// witness proves ONE element is inside without saying where.
//
// The math is the RSA accumulator, plain and public: the root is the
// product of every element modulo the modulus N; element i's witness is
// the product of all the OTHER elements; the verifier checks
//     witness^element === root   (mod N)
// Inverting that for a foreign element is the RSA problem: a stranger
// cannot ride a witness in. And the root hides the set's size — an
// outsider cannot grind subsets against it, because the leaves behind
// the elements are blinded by salts they do not hold.
//
// Honest edges, stated here and in the README:
// - the membership is in the VENDOR's accumulator, so it carries the
//   same trust as every vendor-signed surface: it becomes meaningful
//   next to the newest WITNESSED checkpoint, never alone.
// - witnesses never use the factorization (p, q) — products and modular
//   exponentiation only — so the vendor can witness without keeping the
//   trapdoor handy, and the acc sends nothing positional anywhere.

export const ACC_PRIME_TAG = 'Deal acc prime v1';
export const ACC_ELEMENT_TAG = 'Deal acc element v1';

// ---- bigint helpers -------------------------------------------------------

function bytesToBigInt(bytes) {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

function bigIntToHex(value, minBytes = 0) {
  const text = value.toString(16);
  const padded = text.length % 2 ? `0${text}` : text;
  const want = 2 * minBytes;
  return padded.length < want ? padded.padStart(want, '0') : padded;
}

function hexToBigInt(hex) {
  return BigInt(hex === '' ? '0' : `0x${hex}`);
}

export function powMod(base, exp, mod) {
  if (mod <= 1n) return 0n;
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

// ---- primes ---------------------------------------------------------------

const SMALL_PRIMES = (() => {
  const top = 65536;
  const sieve = new Uint8Array(top);
  const primes = [];
  for (let i = 2; i < top; i += 1) {
    if (!sieve[i]) {
      primes.push(BigInt(i));
      for (let m = i * 2; m < top; m += i) sieve[m] = 1;
    }
  }
  return primes;
})();

function isProbablePrime(candidate, rounds = 40) {
  if (candidate < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (candidate === p) return true;
    if (candidate % p === 0n) return false;
  }
  // Miller-Rabin with bases derived from the candidate: deterministic
  // and reproducible, which the tests want; at this bit size a random
  // base buys almost nothing over a fresh 8-bit base per round.
  let d = candidate - 1n;
  let r = 0;
  while ((d & 1n) === 0n) { d >>= 1n; r += 1; }
  for (let i = 0; i < rounds; i += 1) {
    // the base is derived from the CANDIDATE too (attack round two, finding
    // 5): with candidate-constant bases, composites fooling the fixed set
    // are universal pseudoprimes in principle.
    const raw = bytesToBigInt(H(
      ACC_PRIME_TAG,
      bigIntToHex(candidate, 32),
      new Uint8Array([i & 255, i >> 8]),
    )) % (candidate - 3n);
    const base = raw + 2n;
    let x = powMod(base, d, candidate);
    if (x === 1n || x === candidate - 1n) continue;
    let witnessComposite = true;
    for (let j = 1; j < r; j += 1) {
      x = (x * x) % candidate;
      if (x === candidate - 1n) { witnessComposite = false; break; }
      if (x === 1n) { witnessComposite = true; break; }
    }
    if (witnessComposite) return false;
  }
  return true;
}

// ---- deterministic modulus -------------------------------------------------

const modulusCache = new Map(); // `seed|bits` -> { n, p, q, bits } (trapdoor internal)

function deriveCandidate(seedBytes, label, k, bits) {
  let value = bytesToBigInt(H(ACC_PRIME_TAG, seedBytes, new Uint8Array([label, k & 255, k >> 8])));
  // stretch the digest to a prime-size odd candidate
  while (value < 1n << BigInt(bits - 1)) {
    value = (value << 256n) | bytesToBigInt(H(ACC_PRIME_TAG, bytesToHexPad(value)));
  }
  value |= 1n << BigInt(bits - 1); // full size
  value |= 1n;                     // odd
  return value;
}

function bytesToHexPad(value) {
  return bigIntToHex(value, 32);
}

function findPrime(seedBytes, label, bits) {
  for (let k = 0; ; k += 1) {
    const candidate = deriveCandidate(seedBytes, label, k, bits);
    if (isProbablePrime(candidate)) return candidate;
  }
}

// Deterministic from (seed, bits): the tests pin the same modulus every
// run, and one engine keeps one stable N across all its checkpoints.
// Production callers hand in RANDOM seeds, and must never share one seed
// between two engines: a seed pins a factorization, so its holder could
// factor another engine's N. The engine never needs the trapdoor to
// witness — this rule is defense in depth.
//
// Attack round two, finding 4 / API F1: the trapdoor is no longer part of
// the answer. (p, q) stay inside this module's cache; the public return is
// { n, bits } only. A caller holding the engine object can no longer read
// the factorization out of it.
export function generateModulus({ seed, bits = 2048 }) {
  if (typeof seed !== 'string' || !/^[0-9a-f]{64}$/.test(seed)) {
    throw new Error('The accumulator needs a seed: exactly 32 bytes of lowercase hex.');
  }
  if (![1024, 2048, 3072, 4096].includes(bits)) {
    throw new Error('The accumulator modulus is 1024, 2048, 3072 or 4096 bits.');
  }
  const cacheKey = `${seed.toLowerCase()}|${bits}`;
  const cached = modulusCache.get(cacheKey);
  if (cached) return { n: cached.n, bits: cached.bits };
  const seedBytes = hexToBytes(seed);
  const half = Math.floor(bits / 2);
  const p = findPrime(seedBytes, 1, half);
  let q = findPrime(seedBytes, 2, half);
  if (q === p) q = findPrime(seedBytes, 3, half);
  const key = { n: p * q, p, q, bits };
  modulusCache.set(cacheKey, key);
  return { n: key.n, bits: key.bits };
}

// ---- elements, roots, witnesses --------------------------------------------

// The element for one leaf: a domain-separated hash of the BLINDED leaf
// bytes as an integer, forced odd. No position, no size — just identity.
export function elementOf(leafBytesHex) {
  const bytes = hexToBytes(leafBytesHex);
  const element = bytesToBigInt(H(ACC_ELEMENT_TAG, bytes)) | 1n;
  return bigIntToHex(element, 32);
}

// guard: two leaves hashing to one element (a real collision, or a
// vendor committing the same blinded leaf twice) would break the
// product math in both directions, so refuse instead of absorbing.
function distinct(elements) {
  const seen = new Set();
  for (const element of elements) {
    if (seen.has(element)) {
      throw new Error('Two leaves map to one accumulator element — regenerate the salt.');
    }
    seen.add(element);
  }
}

export function accRootOf(elementsHex, modulusHex) {
  distinct(elementsHex);
  const n = hexToBigInt(modulusHex);
  // the set sits in the EXPONENT: root = g^(product of elements) mod n.
  // The product stays a big integer (no reduction), and powMod eats it
  // bit by bit. Then witness^element = g^(product·element) = root, which
  // is the whole membership check.
  let product = 1n;
  for (const element of elementsHex) product *= hexToBigInt(element);
  return bigIntToHex(powMod(2n, product, n), 32);
}

// witness for element at index i: g^(product of all the OTHER elements)
// (modulo n). Cost is linear in the set size; the trapdoor is unused.
export function accWitness(elementsHex, index, modulusHex) {
  if (!Number.isInteger(index) || index < 0 || index >= elementsHex.length) {
    throw new Error('The witness needs an element that is in the set.');
  }
  const n = hexToBigInt(modulusHex);
  let product = 1n;
  for (let i = 0; i < elementsHex.length; i += 1) {
    if (i !== index) product *= hexToBigInt(elementsHex[i]);
  }
  // pad the witness to the modulus's own width, so hex round-trips cleanly
  const width = Math.ceil((n.toString(2).length + 7) / 8);
  return bigIntToHex(powMod(2n, product, n), width);
}

// The whole blind surface in one call for the auditor: is this element a
// member of the tree committed in the (root, n) pair?
export function verifyBlindMembership({ root, n }, elemHex, witnessHex) {
  try {
    if (!root || !n || !elemHex || witnessHex === undefined) return false;
    const modulus = hexToBigInt(n);
    if (modulus < 7n) return false;
    const expected = hexToBigInt(root);
    // degenerate commitments verify nothing: root 0 and root 1 are the
    // constants any witness satisfies or trivially forges, and element 0
    // makes witness^0 === 1 for ANY witness (attack round two, finding 3).
    if (expected === 0n || expected === 1n) return false;
    const w = hexToBigInt(witnessHex);
    const e = hexToBigInt(elemHex);
    if (e <= 1n) return false;
    return powMod(w, e, modulus) === expected % modulus;
  } catch {
    return false;
  }
}
