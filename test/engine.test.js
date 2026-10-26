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
  const status = engine.disputeStatus(d);
  assert.equal(status.state, 'resolved');
  assert.equal(status.verdict, 'settled');
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

test('engine: rotation mid-history — the new key continues the line, silently is impossible', () => {
  const at = 1_700_000_000_000;
  let clock = at;
  const engine = createEngine({ vendor: 'Maria Phones', now: () => clock });
  const buyer = generateKey();
  const w1 = generateKey();
  logDeal(engine, buyer, { dealId: 'd-1', amount: '1', at: clock });
  const stc1 = engine.checkpoint({ at: clock + 1000 });
  const oldKeyBefore = stc1.key;

  // rotate: old + new both sign one record; the checkpoint path switches keys
  const newVendor = generateKey();
  const rotation = engine.rotateVendorKey(newVendor.secretKey);
  assert.equal(rotation.body.oldKey, oldKeyBefore);
  assert.equal(rotation.body.newKey, newVendor.publicKey);
  assert.ok(rotation.sigs[oldKeyBefore] && rotation.sigs[newVendor.publicKey]);

  clock += 2000;
  logDeal(engine, buyer, { dealId: 'd-2', amount: '1', at: clock });
  const stc2 = engine.checkpoint({ at: clock + 1000, witnessRegistry: [w1.publicKey] });
  engine.witness(w1.secretKey);
  assert.equal(stc2.key, newVendor.publicKey, 'the new key signs after the switch');
  assert.equal(stc2.body.prevHead, stc1.head, 'the line continues across the rotation');

  const pub = engine.publicState({ now: clock + 2000 });
  assert.equal(pub.count, 2);
  assert.equal(pub.standing.current, true, 'rotation does not break standing');
  assert.equal(pub.standing.details.extendsPrior, true);
});

test('engine: revocation mid-history — old checkpoints keep standing, new ones do not count', () => {
  const at = 1_700_000_000_000;
  let clock = at;
  const engine = createEngine({ vendor: 'Two Phones', now: () => clock });
  const buyer = generateKey();
  const w1 = generateKey();
  logDeal(engine, buyer, { dealId: 'd-1', amount: '1', at: clock });
  const stc1 = engine.checkpoint({ at: clock + 1000, witnessRegistry: [w1.publicKey] });
  engine.witness(w1.secretKey);
  clock += 2000; // revocation happens AFTER the honest checkpoint exists

  engine.revokeVendorKey();
  clock += 5000;

  // a thief holding the now-retired key extends the line: the STC verifies
  // cryptographically, but the key timeline refuses checkpoints dated after
  // revocation — it never reaches the count or the size history
  const forged = engine.checkpoint({ at: clock });
  assert.equal(forged.key, stc1.key, 'the thief signs with the stolen key');

  const pub = engine.publicState({ now: clock });
  assert.equal(pub.count, 1, 'the pre-revocation witnessed count stands');
  assert.deepEqual(pub.sizeHistory.map((row) => row.size), [1], 'the forgery is not in the history');
  assert.equal(pub.standing.current, true, 'revocation does not erase the honest past');
});

test('engine: a raw dealId cannot dodge uniqueness — the log stores what the signatures bind', () => {
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const buyer = generateKey();
  // both raw bodies coerce through recordBody to dealId '[object Object]',
  // but their titles (and so hashes, and signatures) differ: the old log
  // keyed uniqueness on the RAW field and committed both, doubling the
  // count and leaving one row unaddressable by any dealId query. The log
  // keys on the normalized body — the bytes the signatures actually bind
  // — one of which is also permanently un-voidable/revealable.
  const make = (title, rawDealId) => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic,
      buyer: buyer.publicKey,
      currency: 'xmr',
      dealId: '[object Object]',
      title,
      amount: '1',
      at: clock,
    }));
    return coSignRecord({ ...vendorSigned, body: { ...vendorSigned.body, dealId: rawDealId } }, buyer.secretKey);
  };
  engine.commitDeal(make('iPhone 13', { a: 1 }));
  assert.throws(() => engine.commitDeal(make('Pixel 7', { b: 2 })), /already committed/);
  engine.checkpoint({});
  assert.equal(engine.publicState({}).count, 1);
  assert.equal(engine.revealDeal('[object Object]').granted, true);
});

test('engine: distinct dealIds still commit normally', () => {
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const buyer = generateKey();
  const make = (dealId, title) => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic,
      buyer: buyer.publicKey,
      currency: 'xmr',
      dealId,
      title,
      amount: '1',
      at: clock,
    }));
    return coSignRecord({ ...vendorSigned, body: { ...vendorSigned.body, dealId } }, buyer.secretKey);
  };
  engine.commitDeal(make('d-1', 'iPhone 13'));
  engine.commitDeal(make('d-2', 'Pixel 7'));
  engine.checkpoint({});
  assert.equal(engine.publicState({}).count, 2);
  assert.equal(engine.revealDeal('d-1').granted, true);
  assert.equal(engine.revealDeal('d-2').granted, true);
});

test('engine: the leaf salt mixes in the buyer\'s randomness, stated in the response', () => {
  const clock = 1_700_000_000_000;
  const buyer = generateKey();
  const recordFor = (engine) => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic,
      buyer: buyer.publicKey,
      currency: 'xmr',
      dealId: 'd-salt',
      amount: '1',
      at: clock,
    }));
    return coSignRecord(vendorSigned, buyer.secretKey);
  };
  const one = createEngine({ now: () => clock });
  const two = createEngine({ now: () => clock });
  const a = one.commitDeal(recordFor(one), 'ab'.repeat(8));
  const b = two.commitDeal(recordFor(two), (a.salt === 'never' ? '' : 'cd').repeat(8));
  assert.equal(a.saltProvenance, 'vendor+buyer');
  assert.equal(b.saltProvenance, 'vendor+buyer');
  assert.notEqual(a.salt, b.salt, 'different buyer randomness, different even-so records');
  assert.equal(a.salt.length, 64, 'the mixed salt is a hash: 32 bytes');
});

test('engine: degenerate buyer salt throws — the mix needs real entropy', () => {
  const clock = 1_700_000_000_000;
  const buyer = generateKey();
  const engine = createEngine({ now: () => clock });
  const record = (() => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic,
      buyer: buyer.publicKey,
      currency: 'xmr',
      dealId: 'd-short-salt',
      amount: '1',
      at: clock,
    }));
    return coSignRecord(vendorSigned, buyer.secretKey);
  })();
  assert.throws(() => engine.commitDeal(record, ''), /entropy|hex|salt/i);
  assert.throws(() => engine.commitDeal(record, 'abc'), /hex|salt/i, 'odd length is not hex');
  assert.throws(() => engine.commitDeal(record, 'ab'.repeat(4)), /entropy/i, '4 bytes is not enough');
});

test('engine: the audit window still opens when the leaf is mixed-salted', () => {
  const clock = 1_700_000_000_000;
  const buyer = generateKey();
  const engine = createEngine({ now: () => clock });
  logDealMixed(engine, buyer);
  function logDealMixed(eng, byr) {
    const vendorSigned = signRecord(eng.keys.secretKey, recordBody({
      vendor: eng.vendorPublic,
      buyer: byr.publicKey,
      currency: 'xmr',
      dealId: 'd-mixed',
      amount: '0.5',
      at: clock,
    }));
    eng.commitDeal(coSignRecord(vendorSigned, byr.secretKey), 'ef'.repeat(8));
  }
  engine.checkpoint({});
  const reveal = engine.revealDeal('d-mixed');
  assert.equal(reveal.granted, true);
  assert.equal(reveal.check, true, 'the window proves inclusion in the mixed tree');
});

test('engine: no buyer salt — the vendor-only path stays, visibly labeled', () => {
  const clock = 1_700_000_000_000;
  const step = { engine: createEngine({ now: () => clock }) };
  const buyer = generateKey();
  const vendorSigned = signRecord(step.engine.keys.secretKey, recordBody({
    vendor: step.engine.vendorPublic,
    buyer: buyer.publicKey,
    currency: 'xmr',
    dealId: 'd-fallback',
    amount: '1',
    at: clock,
  }));
  const out = step.engine.commitDeal(coSignRecord(vendorSigned, buyer.secretKey));
  assert.equal(out.saltProvenance, 'vendor', 'the provenance tells the truth about who mixed');
  assert.equal(out.salt.length >= 32, true);
});
