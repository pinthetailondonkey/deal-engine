import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import {
  generateModulus, elementOf, accRootOf, accWitness,
  verifyBlindMembership,
} from '../src/accumulator.js';
import { signRecord, recordBody, coSignRecord } from '../src/record.js';
import { createEngine } from '../src/engine.js';
import { bytesHex } from './helpers.js';
import { makeTree } from '../src/merkle.js';
import { encodeParts } from '../src/canonical.js';

const SEED = 'aa'.repeat(32);

let MODUS; // generated once for the whole run: prime search is the slow part

before(() => {
  MODUS = generateModulus({ seed: SEED, bits: 1024 });
});

test('accumulator: the modulus is deterministic from its seed', () => {
  const again = generateModulus({ seed: SEED, bits: 1024 });
  assert.equal(again.n, MODUS.n, 'same seed, same primes');
  const other = generateModulus({ seed: 'bb'.repeat(32), bits: 1024 });
  assert.notEqual(other.n, MODUS.n, 'a different seed does not share the factorization');
});

test('accumulator: membership verifies for every index, without a position', () => {
  const leafs = Array.from({ length: 7 }, (_, i) => bytesHex(makeTree(Array.from({ length: 5 }, (_, j) => encodeParts([`leaf-${i}`, String(j)]))).mthAll()));
  const elements = leafs.map((leaf) => elementOf(leaf));
  const root = accRootOf(elements, MODUS.n);
  for (let i = 0; i < elements.length; i += 1) {
    const witness = accWitness(elements, i, MODUS.n);
    assert.equal(verifyBlindMembership({ root, n: MODUS.n }, elements[i], witness),
      true, `index ${i} is provably a member`);
    assert.equal(verifyBlindMembership({ root, n: MODUS.n }, elementOf('deadc0de'), witness),
      false, 'a stranger element cannot ride this witness in');
  }
});

test('accumulator: a tampered witness fails, and so does a swapped root', () => {
  const leafs = ['11', '22', '33'].map((h) => 'ab'.repeat(1) + h);
  const elements = leafs.map(elementOf);
  const root = accRootOf(elements, MODUS.n);
  const witness = accWitness(elements, 0, MODUS.n);
  const corrupt = (BigInt(`0x${witness}`) ^ 1n).toString(16);
  assert.equal(verifyBlindMembership({ root, n: MODUS.n }, elements[0], corrupt.toString(16)), false);
  assert.equal(verifyBlindMembership({ root: 'ee'.repeat(64), n: MODUS.n }, elements[0], witness), false);
});

test('engine: blind reveal proves membership, leaks no index and no size', async (t) => {
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const buyer = generateKey();
  const log = (id, at) => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic, buyer: buyer.publicKey,
      currency: 'xmr', dealId: id, amount: '1', at,
    }));
    const both = coSignRecord(vendorSigned, buyer.secretKey);
    engine.commitDeal(both, '11'.repeat(8));
  };
  log('d-blind-1', clock);
  log('d-blind-2', clock);
  log('d-blind-3', clock);
  const stc = engine.checkpoint({ accSeed: SEED });
  assert.ok(stc.body.accN, 'the checkpoint now carries the accumulator modulus');
  assert.ok(stc.body.accRoot, 'and an accumulator root');

  const blind = engine.revealDealBlind('d-blind-2');
  assert.equal(blind.granted, true);
  assert.equal(verifyBlindMembership({ root: blind.root, n: blind.n }, blind.elem, blind.witness), true);
  assert.equal(blind.index, undefined, 'no position in the answer');
  assert.equal(blind.treeSize, undefined, 'no size in the answer');
  assert.equal(blind.proof, undefined, 'no Merkle co-path that could triangulate the position');

  // all three deals are individually provable, none of them positioned
  for (const id of ['d-blind-1', 'd-blind-3']) {
    const one = engine.revealDealBlind(id);
    assert.equal(verifyBlindMembership({ root: one.root, n: one.n }, one.elem, one.witness), true, `${id} provable too`);
  }

  // and the merkle surface co-exists: the full window still works
  const full = engine.revealDeal('d-blind-1');
  assert.equal(full.granted, true);
  assert.equal(full.check, true);
});

test('engine: a fresh commit that the newest checkpoint never counted is refused membership, not faked', () => {
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const buyer = generateKey();
  const log = (id) => {
    const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
      vendor: engine.vendorPublic, buyer: buyer.publicKey,
      currency: 'xmr', dealId: id, amount: '3', at: clock,
    }));
    engine.commitDeal(coSignRecord(vendorSigned, buyer.secretKey), '22'.repeat(8));
  };
  log('d-counted');
  engine.checkpoint({ accSeed: SEED });
  log('d-invisible');
  const late = engine.revealDealBlind('d-invisible');
  assert.equal(late.granted, false, 'a checkpointed accumulator cannot vouch for later records');
  assert.equal(late.reason, 'not in the newest checkpoint');
});

test('engine: without the option the accumulator is dormant and the window says so', () => {
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const buyer = generateKey();
  const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
    vendor: engine.vendorPublic, buyer: buyer.publicKey,
    currency: 'xmr', dealId: 'd-plain', amount: '1', at: clock,
  }));
  engine.commitDeal(coSignRecord(vendorSigned, buyer.secretKey), '33'.repeat(8));
  engine.checkpoint({});
  const blind = engine.revealDealBlind('d-plain');
  assert.equal(blind.granted, false);
  assert.equal(blind.reason, 'no published accumulator');
  assert.equal(engine.checkpoint({}).body.accRoot, '', 'old-shape checkpoints stay payload-free');
});
