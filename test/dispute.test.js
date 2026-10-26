import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { signDispute, verifyDispute, signResolution, verifyResolution, disputeStatus } from '../src/dispute.js';

const t = (n) => 1_700_000_000_000 + n;
const A = generateKey(); // filer
const B = generateKey(); // accused
const arbiter = generateKey();

function dispute() {
  return signDispute(A.secretKey, {
    about: 'aa'.repeat(32),
    from: A.publicKey,
    against: B.publicKey,
    claim: 'The screen was cracked on arrival.',
    at: t(1),
  });
}

test('dispute: a valid filing verifies; tampering does not', () => {
  const d = dispute();
  assert.equal(verifyDispute(d), true);
  const forged = JSON.parse(JSON.stringify(d));
  forged.body.claim = 'Something else entirely.';
  assert.equal(verifyDispute(forged), false);
});

test('dispute: nobody files a dispute against themselves', () => {
  assert.throws(() => signDispute(A.secretKey, {
    about: 'aa'.repeat(32),
    from: A.publicKey,
    against: A.publicKey,
    claim: 'Self-dispute.',
    at: t(1),
  }), /oneself/);
});

test('dispute: resolution needs both parties or filer+arbiter — one stranger cannot forge', () => {
  const d = dispute();
  const settled = signResolution([A.secretKey, B.secretKey], d, 'settled', t(2));
  assert.equal(verifyResolution(d, settled), true);
  // B alone cannot "resolve"
  const unilateral = signResolution([B.secretKey], d, 'settled', t(2));
  assert.equal(verifyResolution(d, unilateral), false);
  // filer + arbiter suffices (the arbitration path from the receipt spec)
  const arbitrated = signResolution([A.secretKey, arbiter.secretKey], d, 'overturned', t(2), {
    arbiterKeys: [arbiter.publicKey],
  });
  assert.equal(verifyResolution(d, arbitrated, [arbiter.publicKey]), true);
  // an unknown key cannot sign a resolution at all
  const stranger = generateKey();
  const forged = signResolution([A.secretKey, stranger.secretKey], d, 'settled', t(2), {
    arbiterKeys: [stranger.publicKey],
  });
  assert.equal(verifyResolution(d, forged), false); // stranger is not admitted here
});

test('dispute: only the filer can withdraw — this is the anti-extortion valve', () => {
  const d = dispute();
  assert.throws(() => signResolution([B.secretKey], d, 'withdrawn', t(2)), /filer/);
  const withdrawn = signResolution([A.secretKey], d, 'withdrawn', t(2));
  assert.equal(verifyResolution(d, withdrawn), true);
});

test('dispute: open vs resolved — resolved stops the ⚠ headline', () => {
  const d = dispute();
  assert.deepEqual(disputeStatus(d, []), { state: 'open', verdict: '' });
  const settled = signResolution([A.secretKey, B.secretKey], d, 'settled', t(2));
  assert.deepEqual(disputeStatus(d, [settled]), { state: 'resolved', verdict: 'settled' });
  // a forged resolution next to a real one does not overwrite the verdict
  const fake = JSON.parse(JSON.stringify(settled));
  fake.body.verdict = 'overturned';
  assert.deepEqual(disputeStatus(d, [settled, fake]), { state: 'resolved', verdict: 'settled' });
});
