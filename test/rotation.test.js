import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import {
  signRotation, verifyRotation, rotationIsDualSigned,
  signRevocation, verifyRevocation,
  keyTimelineResolve,
} from '../src/rotation.js';
import { admittedWitness } from '../src/checkpoint.js';
import { makeTree } from '../src/merkle.js';
import { encodeParts } from '../src/canonical.js';
import { bytesHex } from './helpers.js';

const t0 = 1_700_000_000_000;

function stcOf(pair, over = {}) {
  const size = 5;
  return {
    v: 1,
    tag: 'Deal checkpoint v1',
    head: 'zz'.repeat(32), // placeholder; overwritten below via checkpointHash
    body: {
      v: 1,
      seq: 1,
      treeSize: size,
      root: bytesHex(makeTree(Array.from({ length: size }, (_, i) => encodeParts([over.seed ?? 's', String(i)]))).mthAll()),
      prevHead: over.prevHead ?? '',
      issuedAt: over.at ?? t0,
      keyId: over.keyId ?? '',
      witnessRegistry: over.witnessRegistry ?? '',
    },
    key: pair.publicKey,
    sig: '',
  };
}

test('rotation: a live key rotates only with BOTH signatures', () => {
  const oldPair = generateKey();
  const newPair = generateKey();
  const rotation = signRotation(oldPair.secretKey, newPair.secretKey, 'vendor', t0);
  assert.equal(rotation.body.role, 'vendor');
  assert.equal(rotation.body.oldKey, oldPair.publicKey);
  assert.equal(rotation.body.newKey, newPair.publicKey);
  assert.equal(rotationIsDualSigned(rotation), true);
  assert.equal(verifyRotation(rotation), true);

  // one-sided: the silent rotation the thief wants
  const oneSided = { ...rotation, sigs: { [oldPair.publicKey]: rotation.sigs[oldPair.publicKey] } };
  assert.equal(rotationIsDualSigned(oneSided), false);
  assert.equal(verifyRotation(oneSided), false);

  // the thief's fully-forged version: both sigs claimed, body tampered
  const forged = JSON.parse(JSON.stringify(rotation));
  forged.body.at = t0 + 1; // any body change kills both signatures
  assert.equal(verifyRotation(forged), false);
});

test('rotation: role must be vendor or witness; same key rotating to itself is refused', () => {
  const pair = generateKey();
  assert.throws(() => signRotation(pair.secretKey, pair.secretKey, 'vendor', t0));
  assert.throws(() => signRotation(pair.secretKey, generateKey().secretKey, '', t0));
});

test('revocation: a key retires itself, and only itself', () => {
  const pair = generateKey();
  const revocation = signRevocation(pair.secretKey, 'vendor', t0);
  assert.equal(verifyRevocation(revocation), true);
  assert.equal(revocation.body.key, pair.publicKey);
  // nobody can retire someone else's key
  assert.throws(() => signRevocation(generateKey().secretKey, 'vendor', t0, pair.publicKey), /retire itself|itself only/i);
});

test('timeline: signatures before revocation count; after do not', () => {
  const pair = generateKey();
  const revokedAt = t0 + 5_000;
  const timeline = [{ kind: 'vendor', publicKey: pair.publicKey, from: t0, until: { kind: 'revoked', at: revokedAt } }];
  assert.deepEqual(keyTimelineResolve(timeline, pair.publicKey, t0 + 1_000), { valid: true, role: 'vendor' });
  assert.deepEqual(keyTimelineResolve(timeline, pair.publicKey, revokedAt + 1), { valid: false, reason: 'revoked' });
});

test('timeline: rotation switches authority at the recorded tick, not before', () => {
  const a = generateKey();
  const b = generateKey();
  const timeline = [
    { kind: 'vendor', publicKey: a.publicKey, from: t0, until: { kind: 'rotated', at: t0 + 10_000 } },
    { kind: 'vendor', publicKey: b.publicKey, from: t0 + 10_000, until: null },
  ];
  assert.deepEqual(keyTimelineResolve(timeline, a.publicKey, t0 + 9_999), { valid: true, role: 'vendor' });
  assert.deepEqual(keyTimelineResolve(timeline, a.publicKey, t0 + 10_001), { valid: false, reason: 'retired' });
  assert.deepEqual(keyTimelineResolve(timeline, b.publicKey, t0 + 10_000), { valid: true, role: 'vendor' });
  assert.deepEqual(keyTimelineResolve(timeline, b.publicKey, t0 + 5_000), { valid: false, reason: 'not yet' });
  assert.deepEqual(keyTimelineResolve(timeline, generateKey().publicKey, t0), { valid: false, reason: 'unknown' });
});

test('standing: fork evidence signed pre-revocation still counts FORKED; post-revocation is suspect, never a verdict', async (t) => {
  const { standing } = await import('../src/standing.js');
  const { signCheckpoint, keyIdOf, forkEvidence } = await import('../src/checkpoint.js');
  const vendorPair = generateKey();

  const stc = (at, over = {}) => signCheckpoint(vendorPair.secretKey, {
    seq: over.seq ?? 1,
    treeSize: over.treeSize ?? 5,
    root: bytesHex(makeTree(Array.from({ length: over.treeSize ?? 5 }, (_, i) => encodeParts([over.seed ?? 's', String(i)]))).mthAll()),
    prevHead: over.prevHead ?? 'aa'.repeat(32),
    issuedAt: at,
    keyId: keyIdOf(vendorPair.publicKey),
    witnessRegistry: over.registry ?? [],
  });

  const parent = stc(t0 - 3_000, { seed: 'base' });
  const oldA = stc(t0 - 2_000, { seq: 2, seed: 'old', prevHead: parent.head });
  const oldB = stc(t0 - 1_000, { seq: 3, treeSize: 7, seed: 'old', prevHead: parent.head });
  const legitEvidence = forkEvidence(oldA, oldB);
  assert.ok(legitEvidence, 'pre-revocation fork evidence is valid evidence');

  const revokedAt = t0;
  const timeline = [{ kind: 'vendor', publicKey: vendorPair.publicKey, from: t0 - 10_000, until: { kind: 'revoked', at: revokedAt } }];

  // a libel attempt: the (now stolen, revoked) key signs NEW checkpoints dated AFTER revocation
  const parent2 = stc(t0 + 500, { seed: 'stolen-parent', seq: 7 });
  const stolenA = stc(t0 + 1_000, { seed: 'stolen', seq: 8, prevHead: parent2.head });
  const stolenB = stc(t0 + 2_000, { seq: 9, treeSize: 9, seed: 'stolen', prevHead: parent2.head });
  const libeled = forkEvidence(stolenA, stolenB);

  const st = standing({
    checkpoints: [stc(t0 + 3_000, { registry: [] })],
    witnessStatements: [],
    forkEvidence: [libeled],
    keyTimeline: timeline,
  }, t0 + 4_000);
  assert.equal(st.forked, false, 'post-revocation checkpoint keys are not genuine: no verdict');
  assert.equal(st.suspectedForkEvidence, true, 'but the attempt is visible');

  const st2 = standing({
    checkpoints: [stc(t0 + 3_000, { registry: [] })],
    witnessStatements: [],
    forkEvidence: [legitEvidence],
    keyTimeline: timeline,
  }, t0 + 4_000);
  assert.equal(st2.forked, true, 'evidence from while the key was live bites');
});

test('witness rotation: new key inherits admission only through a signed rotation on record', () => {
  const witnessOld = generateKey();
  const witnessNew = generateKey();
  const rotation = signRotation(witnessOld.secretKey, witnessNew.secretKey, 'witness', t0);
  const stc = stcOf(generateKey(), { witnessRegistry: [witnessOld.publicKey].join('|') });

  assert.equal(admittedWitness(stc, witnessNew.publicKey, [rotation]), true, 'via rotation');
  assert.equal(admittedWitness(stc, witnessOld.publicKey, []), true, 'direct registry');
  assert.equal(admittedWitness(stc, generateKey().publicKey, [rotation]), false, 'never by self-claim');
  // a forged rotation on a registry that never admitted the old key
  const strangerOld = generateKey();
  const bogus = signRotation(strangerOld.secretKey, witnessNew.secretKey, 'witness', t0);
  assert.equal(admittedWitness(stc, witnessNew.publicKey, [bogus]), false, 'the chain must reach the registry');
});
