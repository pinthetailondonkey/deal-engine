import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { signRecord, verifyRecord, coSignRecord, signVoid, verifyVoid, recordBody } from '../src/record.js';

const t = (n) => 1_700_000_000_000 + n;

function makeParties() {
  return { vendor: generateKey(), buyer: generateKey(), third: generateKey() };
}

function makeRecord(parties, override = {}) {
  const body = recordBody({
    dealId: 'd-001',
    vendor: parties.vendor.publicKey,
    buyer: parties.buyer.publicKey,
    title: 'iPhone 13',
    claim: 'good condition',
    currency: 'xmr',
    amount: '0.5',
    at: t(1),
    ...override,
  });
  return signRecord(parties.vendor.secretKey, body);
}

test('record: valid dual-signed record verifies', () => {
  const parties = makeParties();
  const first = makeRecord(parties);
  assert.equal(verifyRecord(first), false, 'vendor alone is not a deal');
  const both = coSignRecord(first, parties.buyer.secretKey);
  assert.equal(verifyRecord(both), true);
});

test('record: self-dealing is refused at the byte level', () => {
  const parties = makeParties();
  assert.throws(() => makeRecord(parties, { buyer: parties.vendor.publicKey }), /neither|buyer|vendor/);
});

test('record: a tampered field never verifies', () => {
  const parties = makeParties();
  const first = makeRecord(parties);
  const both = coSignRecord(first, parties.buyer.secretKey);
  const forged = JSON.parse(JSON.stringify(both));
  forged.body.amount = '999';
  assert.equal(verifyRecord(forged), false);
});

test('record: role strings cannot spoof — the third key signs nothing', () => {
  const parties = makeParties();
  const first = makeRecord(parties);
  assert.throws(() => signRecord(parties.third.secretKey, first.body, first), /neither the buyer nor the vendor/);
});

test('record: void statements are visible and do not delete', () => {
  const parties = makeParties();
  const both = coSignRecord(makeRecord(parties), parties.buyer.secretKey);
  const voided = signVoid(parties.buyer.secretKey, both, 'refunded', t(2));
  assert.equal(verifyVoid(both, voided), true);
  assert.equal(voided.body.voids, both.hash);
  // the tip-of-truth: the record still verifies; the void sits BESIDE it
  assert.equal(verifyRecord(both), true);
});

test('record: voids must be signed by a party', () => {
  const parties = makeParties();
  const both = coSignRecord(makeRecord(parties), parties.buyer.secretKey);
  assert.throws(() => signVoid(parties.third.secretKey, both, 'not mine', t(2)), /not a party/);
});
