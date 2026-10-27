import { sha256 } from '@noble/hashes/sha2.js';

// Every signed object in the engine has canonical bytes. Cipher learned this
// for receipts (receiptBytes in proofOfTrade.js reports); the checkpoint layer
// dropped it and the log-crypto attacker recomputed the bill. Rule: no signed
// object exists without a byte form.

export function bytesToHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex) {
  const text = String(hex || '');
  if (!/^[0-9a-f]*$/.test(text) || text.length % 2) throw new Error('Not a hex string.');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const SLOT_TAGS = new Uint8Array([0xff, 0xfd]); // field-count tag so |a|b| and |ab| never collide

export function encodeParts(parts) {
  // Length-prefixed concatenation: [sha256(part)][part] per field, so byte
  // boundaries survive joins. This is the join the log-crypto attacker asked
  // to see defined; "H(a || b)" with bare concatenation is not it.
  const chunks = [SLOT_TAGS];
  for (const part of parts) {
    const bytes = part instanceof Uint8Array ? part : new TextEncoder().encode(String(part));
    chunks.push(sha256(bytes), bytes);
  }
  return concatBytes(chunks);
}

export function concatBytes(list) {
  const total = list.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const item of list) {
    out.set(item, at);
    at += item.length;
  }
  return out;
}

export function canonical(value) {
  // Keys sorted, no whitespace, arrays in order. A float is not a coin amount;
  // amounts must already be strings on the way in.
  //
  // INJECTIVE BY CONSTRUCTION (closes the old landmine, documented-deliberate
  // before): no two distinct renderable values share bytes. The old renderer
  // aliased null with undefined and NaN/±Infinity with each other, and dropped
  // undefined-valued keys — so ['a', null] and ['a', undefined] signed alike
  // and {a: undefined} signed as {}. Every *Body() constructor validated types
  // first, so no honest body ever carried those values — but the rule "the
  // engine never feeds them to a signature" was a social discipline, and any
  // NEW surface could break it silently. Now the renderer closes the class
  // itself: undefined, null and each non-finite number carry their own tagged
  // bytes, undefined-valued keys are kept, and a symbol or function — values
  // whose bytes nobody can honestly define — REFUSE loudly instead of
  // rendering, so an alias cannot exist.
  //
  // Scope of the promise, stated: injective over the values this function
  // accepts, exactly. [1] and [1, undefined] stay distinct. A hole is
  // indistinguishable from an undefined element — they ARE the same rendered
  // data — and -0 aliases with 0 because they are one number value, not two.
  if (value === undefined) return '~undefined';
  if (value === null) return '~null';
  if (typeof value === 'bigint') return `~bigint:${value.toString()}`;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return `~number:${value}`;
    return JSON.stringify(value);
  }
  if (typeof value === 'symbol' || typeof value === 'function' || typeof value === 'object' && value instanceof Promise) {
    throw new Error('A signed body refuses this value type: it has no canonical bytes.');
  }
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

export function canonicalBytes(value) {
  return new TextEncoder().encode(canonical(value));
}

// Domain separation on every hash. H('Deal leaf v1', ...) and
// H('Deal STC v1', ...) can never stand in for each other — the leaf-as-node
// replay class, named by the log-crypto attacker.
export function H(tag, ...parts) {
  return sha256(encodeParts([tag, ...parts]));
}

export function hashObject(tag, value) {
  return H(tag, canonicalBytes(value));
}

export function hashHex(tag, value) {
  return bytesToHex(hashObject(tag, value));
}
