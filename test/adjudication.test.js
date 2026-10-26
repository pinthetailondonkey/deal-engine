import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { signCheckpoint, keyIdOf, forkEvidence, signWitnessStatement } from '../src/checkpoint.js';
import { makeTree } from '../src/merkle.js';
import { encodeParts } from '../src/canonical.js';
import { bytesHex } from './helpers.js';
import { adjudicateFork } from '../src/adjudication.js';
import { sign } from '../src/keys.js';
import { canonicalBytes } from '../src/canonical.js';

const t0 = 1_700_000_000_000;

function pair() { return generateKey(); }

function stc(vendorPair, over = {}) {
  const size = over.treeSize ?? 5;
  return signCheckpoint(vendorPair.secretKey, {
    seq: over.seq ?? 1,
    treeSize: size,
    root: bytesHex(makeTree(Array.from({ length: size }, (_, i) => encodeParts([over.seed ?? 's', String(i)]))).mthAll()),
    prevHead: over.prevHead ?? '',
    issuedAt: over.at ?? t0,
    keyId: keyIdOf(vendorPair.publicKey),
    witnessRegistry: over.registry ?? [],
  });
}

// two honest lines from one parent: the fork shape the design describes
function forkShape({ registryA, registryB } = {}) {
  const vendorPair = pair();
  const parent = stc(vendorPair, { seed: 'base', registry: [...registryA ?? [], ...registryB ?? []] });
  const a = stc(vendorPair, { seed: 'lineA', seq: 2, prevHead: parent.head, registry: registryA ?? [] });
  const b = stc(vendorPair, { seed: 'lineB', seq: 2, treeSize: 9, prevHead: parent.head, registry: registryB ?? [] });
  return { vendorPair, evidence: forkEvidence(a, b), a, b };
}

test('adjudication: one witness on BOTH sides proves the fork — no judge, no trust', () => {
  const w = pair();
  const { evidence, a, b, vendorPair } = forkShape({ registryA: [w.publicKey], registryB: [w.publicKey] });
  const statements = [signWitnessStatement(w.secretKey, a), signWitnessStatement(w.secretKey, b)];
  const verdict = adjudicateFork(evidence, statements);
  assert.equal(verdict.verdict, 'fork-proved');
  assert.equal(verdict.sharedWitness, w.publicKey);
  // and it survives an attempt to swap the evidence's roles
  assert.equal(adjudicateFork({ ...evidence, a: evidence.b, b: evidence.a }, statements).verdict, 'fork-proved');
});

test('adjudication: disjoint witness sets stay OPEN — a partition is possible, the design refuses to guess', () => {
  const wA = pair();
  const wB = pair();
  const { evidence, a, b } = forkShape({ registryA: [wA.publicKey], registryB: [wB.publicKey] });
  const statements = [signWitnessStatement(wA.secretKey, a), signWitnessStatement(wB.secretKey, b)];
  const verdict = adjudicateFork(evidence, statements);
  assert.equal(verdict.verdict, 'adjudication-open');
  assert.equal(verdict.sharedWitness, null);
});

test('adjudication: a forged statement on one side cannot buy a shared witness', () => {
  const w = pair();
  const forger = pair();
  const { evidence, a, b } = forkShape({ registryA: [w.publicKey], registryB: [w.publicKey] });
  const honest = signWitnessStatement(w.secretKey, a);
  // the forger fabricates a statement claiming w signed line b — w never
  // signed it, so the sig will not verify against the claimed witness key
  const forged = {
    v: 1,
    tag: 'Deal witness v1',
    witness: w.publicKey,
    body: { v: 1, stcHead: b.head, witnessTime: b.body.issuedAt, prevStcHead: '' },
    sig: sign(forger.secretKey, canonicalBytes({ v: 1, stcHead: b.head, witnessTime: b.body.issuedAt, prevStcHead: '' })),
  };
  const verdict = adjudicateFork(evidence, [honest, forged]);
  assert.equal(verdict.verdict, 'adjudication-open', 'statement signatures are re-checked, not trusted');
});

test('adjudication: the vendor can end it — a self-signed admission keeps one line and drops the other', async () => {
  const { signVendorAdmission, verifyVendorAdmission } = await import('../src/adjudication.js');
  const { vendorPair, evidence, a, b } = forkShape({});
  // the vendor names the line that is real; the other is declared dead
  const admission = signVendorAdmission(vendorPair.secretKey, { keep: a.head, drop: b.head, at: t0 + 5000 });
  assert.equal(verifyVendorAdmission(admission), true);
  assert.equal(verifyVendorAdmission({ ...admission, sig: 'ff'.repeat(64) }), false);
  // admission must be signed by the SAME key that signed the checkpoints
  const strangerAdmission = signVendorAdmission(pair().secretKey, { keep: a.head, drop: b.head, at: t0 + 5000 });
  assert.equal(adjudicateFork(evidence, [], { vendorAdmission: strangerAdmission }).verdict, 'adjudication-open',
    'a stranger cannot adjudicate someone else\'s fork');
  assert.equal(adjudicateFork(evidence, [], { vendorAdmission: admission }).verdict, 'vendor-confirmed');
});

test('standing: FORKED only for proved forks; equal-strength suspicion stays visible, un-accused', async () => {
  const { standing } = await import('../src/standing.js');
  const w = pair();
  const { evidence, a, b } = forkShape({ registryA: [w.publicKey], registryB: [w.publicKey] });
  const statements = [signWitnessStatement(w.secretKey, a), signWitnessStatement(w.secretKey, b)];

  const proved = standing({
    forkEvidence: [evidence],
    witnessStatements: statements,
  }, t0 + 10_000);
  assert.equal(proved.forked, true, 'a double-signed witness makes FORKED computed, not judged');
  assert.equal(proved.suspectedForkEvidence, false);

  // same shape, disjoint witnesses: visible, never a verdict
  const wA = pair();
  const wB = pair();
  const { evidence: ev2, a: a2, b: b2 } = forkShape({ registryA: [wA.publicKey], registryB: [wB.publicKey] });
  const statements2 = [signWitnessStatement(wA.secretKey, a2), signWitnessStatement(wB.secretKey, b2)];
  const open = standing({
    forkEvidence: [ev2],
    witnessStatements: statements2,
  }, t0 + 10_000);
  assert.equal(open.forked, false, 'a partition is not a fork, and the engine does not pretend');
  assert.equal(open.suspectedForkEvidence, true, 'but the incompatible lines are not hidden either');
  assert.equal(open.adjudication, 'open');
});
