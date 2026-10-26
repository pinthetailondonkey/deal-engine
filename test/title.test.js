import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { itemKeyPair, signHop, hopBody, verifyHop, verifyHopChain, truncateTitleLineage } from '../src/title.js';
import { bytesHex } from './helpers.js';

const maria = generateKey();
const jo = generateKey();

test('title: a per-item key is derived, and two items never share one', () => {
  const k1 = itemKeyPair(maria.secretKey, 'imei-111');
  const k2 = itemKeyPair(maria.secretKey, 'imei-222');
  assert.notEqual(k1.publicKey, k2.publicKey);
  assert.notEqual(k1.publicKey, maria.publicKey, 'the master key is not the item key');
  assert.equal(k1.publicKey, itemKeyPair(maria.secretKey, 'imei-111').publicKey, 'derivation is deterministic');
  assert.notEqual(k1.publicKey, itemKeyPair(jo.secretKey, 'imei-111').publicKey);
});

test('title: born hop is dual-signed by attester and first holder', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-111');
  const born = signHop([maria.secretKey, item.secretKey], hopBody({
    kind: 'born',
    itemKey: item.publicKey,
    priorHead: '',
    from: maria.publicKey,
    to: item.publicKey,
    at: 1_700_000_000_000,
  }));
  assert.equal(verifyHop(born), true);
  const chain = verifyHopChain([born]);
  assert.equal(chain.ok, true);
  assert.equal(chain.hasBreak, false);
});

test('title: a flip needs both hands — the previous holder cannot sell alone', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-111');
  const born = signHop([maria.secretKey, item.secretKey], hopBody({
    kind: 'born', itemKey: item.publicKey, priorHead: '',
    from: maria.publicKey, to: item.publicKey, at: 1_700_000_000_000,
  }));
  // maria attempts a unilateral flip to jo
  assert.throws(() => signHop([maria.secretKey], hopBody({
    kind: 'flip', itemKey: item.publicKey, priorHead: born.hash,
    from: maria.publicKey, to: jo.publicKey, at: 1_700_000_100_000,
  })), /to key must sign/);
  // both sign: it verifies and the chain extends
  const flip = signHop([maria.secretKey, jo.secretKey], hopBody({
    kind: 'flip', itemKey: item.publicKey, priorHead: born.hash,
    from: maria.publicKey, to: jo.publicKey, at: 1_700_000_100_000,
  }));
  assert.equal(verifyHop(flip), true);
  assert.equal(verifyHopChain([born, flip]).ok, true);
});

test('title: a broken prior head never verifies as a chain', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-111');
  const flip = signHop([maria.secretKey, jo.secretKey], hopBody({
    kind: 'flip', itemKey: item.publicKey, priorHead: 'aa'.repeat(32),
    from: maria.publicKey, to: jo.publicKey, at: 1_700_000_000_000,
  }));
  assert.equal(verifyHop(flip), true, 'the hop itself is well-signed');
  assert.equal(verifyHopChain([flip]).ok === false, true, 'but the chain it claims does not exist');
  // orphan forgery: no born, no chain, no title
});

test('title: truncation is a lineage break, recorded not hidden', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-111');
  const born = signHop([maria.secretKey, item.secretKey], hopBody({
    kind: 'born', itemKey: item.publicKey, priorHead: '',
    from: maria.publicKey, to: item.publicKey, at: 1_700_000_000_000,
  }));
  const truncation = truncateTitleLineage(jo.secretKey, born, item.publicKey, 1_700_500_000_000);
  const restart = signHop([item.secretKey], hopBody({
    kind: 'anchor', itemKey: item.publicKey, priorHead: truncation.hash,
    from: item.publicKey, to: item.publicKey, at: 1_700_500_000_001,
  }));
  const chain = verifyHopChain([born, truncation, restart]);
  assert.equal(chain.ok, true);
  assert.equal(chain.hasBreak, true, 'the break is visible in the chain, forever');
});
