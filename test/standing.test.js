import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, sign } from '../src/keys.js';
import { standing } from '../src/standing.js';
import {
  signCheckpoint, keyIdOf, signWitnessStatement, signRefusal, CADENCE_MS,
  forkEvidence, WITNESS_TAG,
} from '../src/checkpoint.js';
import { makeTree } from '../src/merkle.js';
import { encodeParts, bytesToHex, H, canonicalBytes } from '../src/canonical.js';
import { signRotation } from '../src/rotation.js';
import { bytesHex } from './helpers.js';

const vendor = generateKey();
function witnessKey() { return generateKey(); }

function realStc(at, { registry = [], rootSeed = 'x', size = 3, prevHead = '', seq = 1 } = {}) {
  return signCheckpoint(vendor.secretKey, {
    seq,
    treeSize: size,
    root: bytesHex(makeTree(Array.from({ length: size }, (_, i) => encodeParts([rootSeed, String(i)]))).mthAll()),
    prevHead,
    issuedAt: at,
    keyId: keyIdOf(vendor.publicKey),
    witnessRegistry: registry,
  });
}

test('standing: nothing but a signed record — a claim, not standing', () => {
  const st = standing({}, 0);
  assert.equal(st.standing, 'vendor-signed-claim');
  assert.equal(st.current, false);
  assert.equal(st.neverAudited, true);
});

// Attack round two (s3): a vendor-confirmed verdict never touched checkpoint
// selection — the line the vendor's OWN admission declared dead stayed the
// newest checkpoint and drove current:true, witnesses and all.
test('standing: the confirmed-dropped line stops driving freshness and count', async () => {
  const { signVendorAdmission } = await import('../src/adjudication.js');
  const w = witnessKey();
  const t = 1_700_000_000_000;
  const parent = realStc(t, { seq: 1 });
  const kept = realStc(t + 1000, { seq: 2, prevHead: parent.head, rootSeed: 'kept' });
  const dropped = realStc(t + 1000, { seq: 2, prevHead: parent.head, rootSeed: 'dropped', size: 9 });
  // the dead line even extends and gets witnessed — the strongest case
  const deadChild = realStc(t + 2000, { seq: 3, prevHead: dropped.head, rootSeed: 'dropped', size: 12, registry: [w.publicKey] });
  const admission = signVendorAdmission(vendor.secretKey, { keep: kept.head, drop: dropped.head, at: t + 3000 });
  const st = standing({
    checkpoints: [parent, kept, dropped, deadChild],
    forkEvidence: [forkEvidence(kept, dropped)],
    vendorAdmission: admission,
    witnessStatements: [signWitnessStatement(w.secretKey, deadChild)],
  }, t + 10_000);
  assert.equal(st.forked, true, 'the fork stays visible');
  assert.equal(st.adjudication, 'closed');
  assert.equal(st.current, false, 'freshness is computed from the KEPT line, not the dead one');
  assert.equal(st.stale, true, 'the kept line was never witnessed — that is the honest answer');
  assert.deepEqual(st.details.adjudicatedKept, [kept.head], 'the verdict surfaces which line was kept');
});

test('standing: witnessed checkpoint inside cadence = CURRENT', () => {
  const w = witnessKey();
  const at = 1_700_000_000_000;
  const stc = realStc(at, { registry: [w.publicKey] });
  const st = standing({
    checkpoints: [stc],
    witnessStatements: [signWitnessStatement(w.secretKey, stc)],
  }, at + 1000);
  assert.equal(st.current, true);
  assert.equal(st.stale, false);
  assert.equal(st.neverAudited, false);
  assert.equal(st.details.extendsPrior, true);
});

test('standing: cadence decay is computed on the observer\'s clock', () => {
  const w = witnessKey();
  const at = 1_700_000_000_000;
  const stc = realStc(at, { registry: [w.publicKey] });
  const st = standing({
    checkpoints: [stc],
    witnessStatements: [signWitnessStatement(w.secretKey, stc)],
  }, at + CADENCE_MS + 1);
  assert.equal(st.current, false);
  assert.equal(st.stale, true);
});

test('standing: an unwitnessed checkpoint never makes CURRENT', () => {
  const at = 1_700_000_000_000;
  const stc = realStc(at); // valid, but nobody witnessed it
  const st = standing({ checkpoints: [stc] }, at + 1000);
  assert.equal(st.current, false);
  assert.equal(st.stale, true);
});

test('standing: continuity breaks when the head chain does not reach', () => {
  const w = witnessKey();
  const old = realStc(1_700_000_000_000, { registry: [w.publicKey], seq: 1, rootSeed: 'a' });
  const fresh = realStc(1_700_000_100_000, { registry: [w.publicKey], seq: 2, rootSeed: 'b' }); // prevHead set to ''!
  const st = standing({
    checkpoints: [old, fresh],
    witnessStatements: [signWitnessStatement(w.secretKey, fresh)],
  }, 1_700_000_200_000);
  assert.equal(st.details.extendsPrior, false);
  // rewrote history and it shows: the line is stale, silently rebuilt
  assert.equal(st.current, true, 'fresh within cadence');
  assert.equal(st.details.extendsPrior, false, 'but the chain is broken');
});

test('standing: fork evidence marks FORKED while everything else still computes', () => {
  const w = witnessKey();
  const at = 1_700_000_000_000;
  const stc = realStc(at, { registry: [w.publicKey], prevHead: 'aa'.repeat(32) });
  const st = standing({
    checkpoints: [stc],
    witnessStatements: [signWitnessStatement(w.secretKey, stc)],
    forkEvidence: [JSON.parse(JSON.stringify({ a: { prevHead: 'aa', body: { prevHead: 'aa' } }, b: { prevHead: 'aa', body: { prevHead: 'aa' } } }))],
  }, at + 1000);
  // the fake evidence does NOT verify: forked stays false, current still computes
  assert.equal(st.forked, false);
  assert.equal(st.current, true);
});

test('standing: signed refusal ages like staleness; unsigned refusal is refused', () => {
  const at = 1_700_000_000_000;
  const signed = signRefusal(vendor.secretKey, at);
  const fresh = standing({ refusals: [signed] }, at + 1000);
  assert.equal(fresh.refused, true, 'a fresh signed refusal shows');
  const old = standing({ refusals: [signed] }, at + CADENCE_MS + 1);
  assert.equal(old.refused, false, 'an old refusal is cold, not damning');
});

test('standing: voided deals sit beside the count — no decrement, ever', () => {
  const at = 1_700_000_000_000;
  // structurally-signed void statements count; garbage does not (F13)
  const body = (record, atV) => ({ v: 1, voids: record, reason: 'refunded', at: atV });
  const voided = (record) => {
    const b = body(record, at);
    return {
      v: 1, tag: 'Deal void v1',
      hash: bytesToHex(H('Deal void v1', canonicalBytes(b))),
      body: b, sigs: { buyer: 'ff'.repeat(64) },
    };
  };
  const st = standing({
    voided: [voided('h1'), voided('h2'), '🔫', { record: 'not-a-void' }],
  }, at);
  assert.equal(st.details.voidedCount, 2, 'signed voids stay visible; emoji and junk do not count');
  assert.equal(st.standing, 'vendor-signed-claim');
});

// Attack round three (protocol P7): one dual-signed rotation dated inside
// the pre-revocation window used to seat the thief's fresh key forever —
// 'unknown' on the timeline counted as "not revoked", so the successor
// spoke on every post-revocation checkpoint. Inheritance now rides a LIVE
// source seat: a key the timeline retired before this checkpoint passes
// its seat to no one; the successor must be listed in a registry instead.
test('standing: a laundered rotation cannot seat a successor from a revoked key', () => {
  const w = witnessKey();        // honest key later stolen
  const successor = witnessKey(); // the thief's fresh key
  const at = 1_700_000_000_000;
  const revokeAt = at + 1000;
  // the vendor honestly lists w in the registry of a post-revocation checkpoint
  const stc = realStc(at + 9000, { registry: [w.publicKey] });
  const rotation = signRotation(w.secretKey, successor.secretKey, 'witness', revokeAt - 1);
  // the thief signs its own statement — signWitnessStatement refuses
  // non-registry keys, which is exactly the front door the laundering
  // rotation was supposed to open
  const thiefBody = {
    v: 1,
    stcHead: stc.head,
    witnessTime: stc.body.issuedAt,
    prevStcHead: '',
  };
  const sSuccessor = {
    v: 1,
    tag: WITNESS_TAG,
    witness: successor.publicKey,
    body: thiefBody,
    sig: sign(successor.secretKey, canonicalBytes(thiefBody)),
  };
  const view = {
    checkpoints: [stc],
    witnessStatements: [sSuccessor],
    witnessRotations: [rotation],
    forkEvidence: [],
    refusals: [],
    sizeHistory: [],
    keyTimeline: [
      { kind: 'vendor', publicKey: vendor.publicKey, from: 0, until: null },
      { kind: 'witness', publicKey: w.publicKey, from: 0, until: { kind: 'revoked', at: revokeAt } },
    ],
    voided: [],
  };
  const st = standing(view, at + 90_000);
  assert.equal(st.neverAudited, true, 'a revoked key seats nobody');
  // control: the vendor ACKNOWLEDGES the successor by listing it — it speaks
  const stc2 = realStc(at + 9000, { registry: [successor.publicKey], seq: 2 });
  const s2 = signWitnessStatement(successor.secretKey, stc2);
  const st2 = standing({ ...view, checkpoints: [stc2], witnessStatements: [s2] }, at + 90_000);
  assert.equal(st2.neverAudited, false, 'a listed successor speaks');
});
