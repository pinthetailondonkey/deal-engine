import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEngine } from '../src/engine.js';
import { generateKey } from '../src/keys.js';
import { recordBody, signRecord, coSignRecord, verifyRecord } from '../src/record.js';
import { verifyInclusionProof } from '../src/merkle.js';
import { bytesHex } from './helpers.js';

test('engine: end-to-end — deals, checkpoint, witness, public standing', () => {
  const at = 1_700_000_000_000;
  let clock = at;
  const engine = createEngine({ vendor: 'Maria Phones', now: () => clock });
  const buyer1 = generateKey();
  const buyer2 = generateKey();

  logDeal(engine, buyer1, { dealId: 'd-1', title: 'iPhone 13', amount: '0.5', at: clock });
  clock += 1000;
  logDeal(engine, buyer2, { dealId: 'd-2', title: 'Pixel 7', amount: '0.2', at: clock });

  // checkpoint with one admitted witness
  const w1 = generateKey();
  const stc = engine.checkpoint({ at: clock + 2000, witnessRegistry: [w1.publicKey] });
  const statement = engine.witness(w1.secretKey);

  const pub = engine.publicState({ now: clock + 3000 });
  assert.equal(pub.count, 2, 'witnessed deals: 2');
  assert.equal(pub.countLabel, 'witnessed deals in the latest checkpoint');
  assert.equal(pub.standing.current, true, 'fresh within cadence');
  assert.equal(pub.standing.neverAudited, false);
  assert.equal(pub.standing.details.extendsPrior, true);
  assert.equal(pub.sizeHistory.length, 1);

  // days pass: the cadence decays on the observer's clock
  const late = engine.publicState({ now: at + 40 * 24 * 3600_000 });
  assert.equal(late.standing.current, false);
  assert.equal(late.standing.stale, true);
});

function logDeal(engine, buyer, spec) {
  const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
    vendor: engine.vendorPublic,
    buyer: buyer.publicKey,
    currency: 'xmr',
    ...spec,
  }));
  const both = coSignRecord(vendorSigned, buyer.secretKey);
  assert.equal(verifyRecord(both), true);
  return engine.commitDeal(both);
}

test('engine: the count is the tree size self-declared in a checkpoint — deltas visible', () => {
  const engine = createEngine({ now: () => 1_700_000_000_000 });
  const buyer = generateKey();
  logDeal(engine, buyer, { dealId: 'd-1', amount: '1', at: 1_700_000_000_000 });
  const stc1 = engine.checkpoint({});
  logDeal(engine, buyer, { dealId: 'd-2', amount: '1', at: 1_700_000_000_001 });
  const stc2 = engine.checkpoint({});
  assert.equal(stc1.body.treeSize, 1);
  assert.equal(stc2.body.treeSize, 2);
  assert.equal(stc2.body.prevHead, stc1.head, 'the second checkpoint extends the first');
  const pub = engine.publicState({});
  assert.deepEqual(pub.sizeHistory.map((row) => row.size), [1, 2]);
});

test('engine: no reveal without an authorized window — no membership oracle', () => {
  const engine = createEngine({ now: () => 1_700_000_000_000 });
  assert.deepEqual(engine.revealDeal('no-such-deal'), { granted: false, reason: 'not in log' });
  const buyer = generateKey();
  logDeal(engine, buyer, { dealId: 'd-1', amount: '0.5', at: 1_700_000_000_000 });
  engine.checkpoint({});
  const reveal = engine.revealDeal('d-1');
  assert.equal(reveal.granted, true);
  assert.equal(reveal.check, true, 'the granted window proves inclusion');
  // the auditor can re-verify the proof against the published root
  assert.equal(verifyInclusionProof(
    fromHex(reveal.leafBytes), 0, reveal.treeSize,
    reveal.proof.map(fromHex), reveal.root,
  ), true);
});

function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

test('engine: voided deals are visible beside the count', () => {
  const engine = createEngine({ now: () => 1_700_000_000_000 });
  const buyer = generateKey();
  logDeal(engine, buyer, { dealId: 'd-1', amount: '0.5', at: 1_700_000_000_000 });
  engine.checkpoint({});
  assert.equal(engine.publicState({}).count, 1);
  assert.equal(engine.publicState({}).standing.details.voidedCount, 0);
  // refund lands on the voided ledger — the witnessed count stays 1
  engine.voidDeal('d-1', buyer.secretKey, 'refunded');
  assert.equal(engine.publicState({}).count, 1, 'the count never decrements');
  assert.equal(engine.publicState({}).standing.details.voidedCount, 1, 'the void is visible');
});

test('engine: disputes resolve, never scream forever', () => {
  const engine = createEngine({ now: () => 1_700_000_000_000 });
  const vendorAlt = generateKey();
  const d = engine.fileDispute(vendorAlt.secretKey, {
    about: 'aa'.repeat(32),
    from: vendorAlt.publicKey,
    against: engine.vendorPublic,
    claim: 'Wrong item.',
    at: 1_700_000_001_000,
  });
  const first = engine.disputeStatus(d);
  assert.equal(first.state, 'open');
  engine.resolveDispute([vendorAlt.secretKey, engine.keys.secretKey], d, 'settled', {});
  assert.deepEqual(engine.disputeStatus(d), { state: 'resolved', verdict: 'settled' });
});

test('engine: refusal and title truncation round out the lifecycle', () => {
  const engine = createEngine({ now: () => 1_700_000_000_000 });
  const refusal = engine.refuseAudit({});
  assert.ok(refusal.body.key);
  const item = engine.title.itemKey('imei-42');
  const born = engine.title.signHop([engine.keys.secretKey, item.secretKey], {
    kind: 'born', itemKey: item.publicKey, priorHead: '',
    from: engine.vendorPublic, to: item.publicKey, at: 1_700_000_000_000,
  });
  const chain = engine.title.verifyChain([born]);
  assert.equal(chain.ok, true);
  const trunc = engine.title.truncate(item.publicKey);
  assert.equal(trunc.body.kind, 'truncation');
});
