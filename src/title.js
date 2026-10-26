import { bytesToHex, H, canonicalBytes, hexToBytes } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';
import { schnorr } from '@noble/curves/secp256k1.js';

// Title chains: per-item custody. What the attack reports forced the design
// to keep, and what they forced it to change:
// - keys are per-item derived, so holding two titles never cross-links.
// - a hop is dual-signed by whoever had it and whoever got it.
// - disputes attach to a hop and RESOLVE through the same machinery as
//   money disputes — no permanent unresolved badge.
// - a truncation is a lineage break, not a badge: the chain must show its
//   new root as the child of a truncation record.
// - the engine does not anchor the item to the physical world. An anchor is
//   an external attestation the engine records and requires, never an
//   engine-computed truth. Honest limitation, stated in the code that would
//   otherwise hide it.

export const HOP_TAG = 'Title hop v1';
export const DISPUTE_ATTACH_TAG = 'Title dispute attach v1';
const ITEM_TAG = 'Deal item v1';

// secp256k1 group order — same constant as keys.js
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function publicKeyFrom(secret) {
  return schnorr.getPublicKey(secret);
}

function hexToBytesLocal(hex) {
  return hexToBytes(hex);
}

export function itemKeyPair(masterSecretKey, itemId) {
  // per-item key: skew = H(item id), priv = H(skew || 'item') + master, mod n.
  // holding two different items' titles shares no key between them.
  const master = masterSecretKey instanceof Uint8Array
    ? masterSecretKey : hexToBytesLocal(masterSecretKey);
  const skew = H(ITEM_TAG, new TextEncoder().encode(String(itemId)));
  const priv = addScalars(H(ITEM_TAG, skew, canonicalBytes('item')), master);
  return { secretKey: priv, publicKey: bytesToHex(publicKeyFrom(priv)) };
}

function addScalars(a, b) {
  let sum = (bigIntFromBytes(a) + bigIntFromBytes(b)) % SECP256K1_ORDER;
  if (sum < 0n) sum += SECP256K1_ORDER;
  return bigIntToBytes(sum);
}

function bigIntFromBytes(bytes) {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
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

export function hopBody(input = {}) {
  return {
    v: 1,
    kind: ['born', 'flip', 'anchor', 'truncation'].includes(input.kind) ? input.kind : '',
    itemKey: String(input.itemKey || '').toLowerCase(),
    priorHead: String(input.priorHead || ''),
    from: String(input.from || '').toLowerCase(),
    to: String(input.to || '').toLowerCase(),
    at: requireAt(input.at),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The hop needs a time.');
  return value;
}

export function hopHash(body) {
  return bytesToHex(H(HOP_TAG, canonicalBytes(body)));
}

// Dual signatures: born is attested+received; flip is given+received;
// anchor admits a registry key; truncation is the vendor's own statement
// that history before a point is lost — it STARTS a lineage, never extends
// an old one wearing a new name.
export function signHop(secretKeys, body) {
  const canonicalBody = hopBody(body);
  if (!canonicalBody.kind) throw new Error('Not a hop kind.');
  if (canonicalBody.kind === 'flip' && canonicalBody.from === canonicalBody.to) {
    throw new Error('A flip that goes nowhere flips nothing.');
  }
  const sigs = {};
  for (const secretKey of [].concat(secretKeys)) {
    sigs[publicKeyOf(secretKey)] = sign(secretKey, canonicalBytes(canonicalBody));
  }
  const required = requiredSignersFor(canonicalBody);
  for (const role of required) {
    if (!sigs[canonicalBody[role]]) throw new Error(`The ${role} key must sign the hop.`);
  }
  return { v: 1, tag: HOP_TAG, hash: hopHash(canonicalBody), body: canonicalBody, sigs };
}

function requiredSignersFor(body) {
  if (body.kind === 'born') return ['from', 'to'];
  if (body.kind === 'flip') return ['from', 'to'];
  if (body.kind === 'anchor') return ['to'];
  return ['from']; // truncation: the holder attests the break alone
}

export function verifyHopChain(hops) {
  // cross-item blinding means the verifier checks hop-key consistency and
  // signer validity, not re-derivation: the same holder showing two chains
  // reveals no shared key.
  let tip = null;
  const sorted = [...(hops || [])].sort((a, b) => a.body.at - b.body.at);
  for (const hop of sorted) {
    if (!verifyHop(hop)) return { ok: false, reason: 'signature' };
    // the FIRST hop roots the chain. Only '' (a born hop) or a truncation
    // (a recorded break that starts a new lineage) may be a root — anything
    // else claims a parent no one showed, so the chain does not exist.
    if (!tip) {
      if (hop.body.priorHead === '' || hop.body.kind === 'truncation') {
        tip = hop;
        continue;
      }
      return { ok: false, reason: 'prior' };
    }
    if (hop.body.priorHead !== tip.hash) return { ok: false, reason: 'prior' };
    tip = hop;
  }
  return { ok: true, tip, hasBreak: sorted.some((hop) => hop.body.kind === 'truncation') };
}

export function verifyHop(hop) {
  try {
    if (!hop?.body || hop.tag !== HOP_TAG) return false;
    if (bytesToHex(H(HOP_TAG, canonicalBytes(hopBody(hop.body)))) !== hop.hash) return false;
    const required = requiredSignersFor(hop.body);
    for (const role of required) {
      const key = hop.body[role];
      if (!key || !hop.sigs?.[key]) return false;
      if (!verify(hop.sigs[key], canonicalBytes(hopBody(hop.body)), key)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function truncateTitleLineage(vendorSecretKey, priorTip, itemKeyPub, at) {
  // a truncation record: new root, parent recorded, prior tip never re-usable
  const body = hopBody({
    kind: 'truncation',
    itemKey: itemKeyPub,
    priorHead: priorTip ? priorTip.hash : '',
    from: publicKeyOf(vendorSecretKey),
    to: publicKeyOf(vendorSecretKey),
    at,
  });
  const sigs = { [body.from]: sign(vendorSecretKey, canonicalBytes(body)) };
  return { v: 1, tag: HOP_TAG, hash: hopHash(body), body, sigs };
}
