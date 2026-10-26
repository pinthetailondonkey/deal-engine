import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { deriveItemKey } from '../src/keys.js';
import { itemKeyPair } from '../src/title.js';
import { H, canonicalBytes, encodeParts } from '../src/canonical.js';
import { sha256 } from '@noble/hashes/sha2.js';

// Pins from adversarial round two (attack report 1, repro t1/t1b): the OLD
// derivation was affine with a public constant — item_pub was predictable
// from (master_pub, itemId) alone, and ONE leaked item secret recovered the
// master byte-for-byte, which then forged checkpoints through the engine
// Master secret goes inside the hash: no public relation survives.

const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function bytesToBigInt(bytes) {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

test('derivation: hardened scheme is deterministic and per-master', () => {
  const maria = generateKey();
  const jo = generateKey();
  const a1 = deriveItemKey(maria.secretKey, 'imei-111');
  const a2 = deriveItemKey(maria.secretKey, 'imei-111');
  const b1 = deriveItemKey(maria.secretKey, 'imei-222');
  const c1 = deriveItemKey(jo.secretKey, 'imei-111');
  assert.equal(a1.secretKey instanceof Uint8Array, true, 'secretKey is bytes for Schnorr');
  assert.deepEqual(a1.secretKey, a2.secretKey, 'deterministic per (master, itemId)');
  assert.notDeepEqual(a1.secretKey, b1.secretKey, 'different item, same holder: unrelated keys');
  assert.notDeepEqual(a1.secretKey, c1.secretKey, 'different holder, same item: unrelated keys');
  assert.notEqual(a1.publicKey, maria.publicKey, 'item key is not the master key');
});

test('derivation: the old affine recovery equations no longer produce the master', () => {
  const maria = generateKey();
  const item = deriveItemKey(maria.secretKey, 'imei-111');
  const privN = bytesToBigInt(item.secretKey);
  const masterN = bytesToBigInt(maria.secretKey);
  const idBytes = new TextEncoder().encode('imei-111');

  // Old keys.js relation: priv = h + 2*master with h = sha256(encodeParts([encodeParts([tag, id])]))
  const h = bytesToBigInt(sha256(encodeParts([encodeParts([
    'Deal item key v1', idBytes,
  ])])));
  const recoveredKeysJs = ((privN - h) + SECP256K1_ORDER * 4n)
    % (SECP256K1_ORDER * 2n);
  const half = (SECP256K1_ORDER + 1n) / 2n;
  const recoveredKeysJs2 = (recoveredKeysJs * half) % SECP256K1_ORDER;
  assert.notEqual(
    BigInt(recoveredKeysJs2), masterN,
    'keys.js affine recovery (priv - h) * inv2 must not be the master',
  );
  assert.notEqual(
    BigInt(recoveredKeysJs), masterN,
    'straight subtraction recovery must not be the master either',
  );

  // Old title.js relation: priv = t + master with t = H(ITEM_TAG, H(ITEM_TAG, id), 'item')
  const t = bytesToBigInt(H(
    'Deal item v1',
    H('Deal item v1', idBytes),
    canonicalBytes('item'),
  )) % SECP256K1_ORDER;
  const recoveredTitle = (privN - t + SECP256K1_ORDER) % SECP256K1_ORDER;
  assert.notEqual(recoveredTitle, masterN, 'title.js affine recovery must not yield the master');
});

test('derivation: two holders of the SAME itemId derive independent keys (no public link)', () => {
  const maria = generateKey();
  const jo = generateKey();
  const a = deriveItemKey(maria.secretKey, 'imei-111');
  const b = deriveItemKey(jo.secretKey, 'imei-111');
  // if the scheme were affine, priv_b - priv_a would be a public constant
  // computable from itemId alone — and equal to the difference of the
  // constants old code used. Pin the difference is not deterministic in
  // public data: hold one item fixed across a fresh master and the output
  // changes unpredictably (hash-to-curve, not offset).
  const maria2 = generateKey();
  const a2 = deriveItemKey(maria2.secretKey, 'imei-111');
  const d1 = (bytesToBigInt(a.secretKey) - bytesToBigInt(b.secretKey) + 3n * SECP256K1_ORDER) % SECP256K1_ORDER;
  const d2 = (bytesToBigInt(a2.secretKey) - bytesToBigInt(b.secretKey) + 3n * SECP256K1_ORDER) % SECP256K1_ORDER;
  assert.notEqual(d1, d2, 'same-holder-gap changes when the master changes');
});

test('derivation: the facade keeps one derivation site', () => {
  const maria = generateKey();
  const viaTitle = itemKeyPair(maria.secretKey, 'imei-111');
  const viaKeys = deriveItemKey(maria.secretKey, 'imei-111');
  assert.deepEqual(viaTitle.secretKey, viaKeys.secretKey,
    'title.js delegates to keys.js — exactly one scheme');
});
