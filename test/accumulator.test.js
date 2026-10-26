import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import {
  generateModulus, elementOf, accRootOf, accWitness,
  verifyBlindMembership,
} from '../src/accumulator.js';
import { verifyBlindMembershipIn } from '../src/checkpoint.js';
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

// Attack round three (crypto finding 6): (root, n) arrive as loose strings
// here, and a relayer who keeps the vendor's honest root but swaps in a
// modulus of their own forges membership for any element. The honest pair
// (root = R, n' = R·(R−1)) satisfies R^e ≡ R (mod n') for EVERY element —
// witness = R, any stranger element, verify. The gates close the paper
// family; the signature-bound surface (verifyBlindMembershipIn below) is
// the real closure.
test('accumulator: a forged modulus built from the root is refused at the door', async () => {
  const buyer = generateKey();
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
    vendor: engine.vendorPublic, buyer: buyer.publicKey,
    currency: 'btc', dealId: 'd-header', amount: '1', at: clock,
  }));
  engine.commitDeal(coSignRecord(vendorSigned, buyer.secretKey), '44'.repeat(8));
  engine.checkpoint({ accSeed: SEED });
  const blind = engine.revealDealBlind('d-header');
  assert.equal(blind.granted, true, 'honest window works');
  const { root } = blind;
  const strangerElem = elementOf('ab'.repeat(21));

  // the paper family: n' = R·(R−1), witness = R — used to verify for any element
  const fakeProduct = (BigInt(`0x${root}`) * (BigInt(`0x${root}`) - 1n)).toString(16);
  assert.equal(verifyBlindMembership({ root, n: fakeProduct }, strangerElem, root), false,
    'n\' = R·(R−1) is even and divisible by the root — refused');
  // odd multiples of the root are refused by divisibility, not parity
  const R = BigInt(`0x${root}`);
  const oddSibling = (R * 3n).toString(16); // odd when R is odd, divisible by R either way
  assert.equal(verifyBlindMembership({ root, n: oddSibling }, strangerElem, root), false,
    'n\' = R·m carries the root inside it — refused');

  // even moduli, tiny moduli and moduli smaller than the root never verify
  assert.equal(verifyBlindMembership({ root, n: '8' }, strangerElem, root), false);
  assert.equal(verifyBlindMembership({ root, n: 'a'.repeat(256) }, strangerElem, root), false,
    'n\' below the root is not a modulus the root could be a residue of');

  // and the honest pair keeps verifying
  assert.equal(verifyBlindMembership({ root, n: blind.n }, blind.elem, blind.witness), true);
});

test('accumulator: verifyBlindMembershipIn binds (root, n) to one signed body', async () => {
  const buyer = generateKey();
  const clock = 1_700_000_000_000;
  const engine = createEngine({ now: () => clock });
  const vendorSigned = signRecord(engine.keys.secretKey, recordBody({
    vendor: engine.vendorPublic, buyer: buyer.publicKey,
    currency: 'btc', dealId: 'd-bound', amount: '2', at: clock,
  }));
  engine.commitDeal(coSignRecord(vendorSigned, buyer.secretKey), '55'.repeat(8));
  const stc = engine.checkpoint({ accSeed: SEED });
  const blind = engine.revealDealBlind('d-bound');

  // the auditor surface: everything read from the signature they re-checked
  assert.equal(verifyBlindMembershipIn(stc, blind.elem, blind.witness), true);

  // garbage checkpoints, swapped bodies and non-members are all refused
  assert.equal(verifyBlindMembershipIn({ ...stc, body: { ...stc.body, accRoot: 'ff'.repeat(64) } },
    blind.elem, blind.witness), false, 'a tampered body fails the signature, so no answer');
  assert.equal(verifyBlindMembershipIn(null, blind.elem, blind.witness), false);
  assert.equal(verifyBlindMembershipIn(stc, elementOf('cd'.repeat(21)), blind.witness), false,
    'the bound surface is still a membership check');
  // a stranger's self-signed checkpoint with their own accumulator is a
  // valid signature but NOT the vendor's — anchoring the key is the
  // auditor's job, and the keyTimeline gate grades it here like everywhere
  const { keyTimelineResolve } = await import('../src/rotation.js');
  const outsider = createEngine({ vendor: 'Stranger', now: () => clock });
  const outsiderBuyer = generateKey();
  const outsiderRecord = coSignRecord(signRecord(outsider.keys.secretKey, recordBody({
    vendor: outsider.vendorPublic, buyer: outsiderBuyer.publicKey,
    currency: 'xmr', dealId: 'd-outsider', amount: '1', at: clock,
  })), outsiderBuyer.secretKey);
  outsider.commitDeal(outsiderRecord, '66'.repeat(8));
  const strangerStc = JSON.parse(JSON.stringify(outsider.checkpoint({ accSeed: 'bb'.repeat(32) })));
  assert.equal(verifyBlindMembershipIn(strangerStc, blind.elem, blind.witness,
    { keyTimeline: [{ kind: 'vendor', publicKey: engine.vendorPublic, from: 0, until: null }] }), false,
    'a stranger-signed body does not speak for the vendor under the timeline');
  assert.equal(keyTimelineResolve([{ kind: 'vendor', publicKey: engine.vendorPublic, from: 0, until: null }],
    stc.key, stc.body.issuedAt).valid, true, 'the honest checkpoint rides its own timeline');
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
