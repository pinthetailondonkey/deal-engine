import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import {
  itemKeyPair, signHop, hopBody, verifyHop, verifyHopChain,
  verifyAnchorHop, truncateTitleLineage,
} from '../src/title.js';
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
  // attack round three (P2): the ITEM KEY signs the break — only the
  // deriver's master secret can produce that key, so the break is
  // self-proving and no verifier needs the master
  const truncation = truncateTitleLineage(item.secretKey, born, item.publicKey, 1_700_500_000_000);
  const restart = signHop([item.secretKey], hopBody({
    kind: 'anchor', itemKey: item.publicKey, priorHead: truncation.hash,
    from: item.publicKey, to: item.publicKey, at: 1_700_500_000_001,
  }));
  // the anchor restart rides the item key when the reader admits its key
  const chain = verifyHopChain([born, truncation, restart], { anchorKeys: [item.publicKey] });
  assert.equal(chain.ok, true);
  assert.equal(chain.hasBreak, true, 'the break is visible in the chain, forever');
  // a STRANGER's truncation grafted onto the honest tip proves nothing —
  // its signer is not the item key, whatever else it signs
  const graft = truncateTitleLineage(itemKeyPair(jo.secretKey, 'other-item').secretKey, born, item.publicKey, 1_700_500_000_002);
  const grafted = verifyHopChain([born, graft, restart], { anchorKeys: [item.publicKey] });
  assert.equal(grafted.ok === false, true, 'a foreign-key truncation is an unproven break');
});

test('title: an anchor chain without the reader registry refuses — never a silent pass', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-311');
  const born = signHop([maria.secretKey, item.secretKey], hopBody({
    kind: 'born', itemKey: item.publicKey, priorHead: '',
    from: maria.publicKey, to: item.publicKey, at: 1_710_000_000_000,
  }));
  const restart = signHop([item.secretKey], hopBody({
    kind: 'anchor', itemKey: item.publicKey, priorHead: born.hash,
    from: item.publicKey, to: item.publicKey, at: 1_710_000_000_001,
  }));
  // no registry at all: refuses outright
  const bare = verifyHopChain([born, restart]);
  assert.equal(bare.ok, false);
  assert.equal(bare.reason, 'anchor-unregistered', 'missing registry never downgrades to keyless');
  // empty array: registered but refuses every anchor, loudly
  const empty = verifyHopChain([born, restart], { anchorKeys: [] });
  assert.equal(empty.ok, false);
  assert.equal(empty.reason, 'anchor-unregistered');
  // malformed junk in the set refuses the same way — no lenient reading
  const junk = verifyHopChain([born, restart], { anchorKeys: [item.publicKey, 'not-hex'] });
  assert.equal(junk.ok, false);
  assert.equal(junk.reason, 'anchor-unregistered');
  // a foreign admitted key refuses the anchor even with a valid registry
  const stranger = generateKey();
  const foreign = verifyHopChain([born, restart], { anchorKeys: [stranger.publicKey] });
  assert.equal(foreign.ok, false);
  assert.equal(foreign.reason, 'anchor-unregistered');
  // anchor-free chains stay registry-free: the born chain tests above pass
  assert.equal(verifyHopChain([born]).ok, true, 'no anchor, no demand');
});

test('title: verifyAnchorHop is the single out-of-chain door', () => {
  const item = itemKeyPair(maria.secretKey, 'imei-321');
  const restart = signHop([item.secretKey], hopBody({
    kind: 'anchor', itemKey: item.publicKey, priorHead: 'aa'.repeat(32),
    from: item.publicKey, to: item.publicKey, at: 1_711_000_000_000,
  }));
  // admitted
  assert.deepEqual(verifyAnchorHop(restart, [item.publicKey]), { ok: true, reason: 'admitted' });
  // each refusal keeps its own shape: registry off, empty, foreign, bad sig
  assert.deepEqual(verifyAnchorHop(restart), { ok: false, reason: 'anchor-unregistered' });
  assert.deepEqual(verifyAnchorHop(restart, []), { ok: false, reason: 'anchor-unregistered' });
  const jo_anchor = signHop([jo.secretKey], hopBody({
    kind: 'anchor', itemKey: item.publicKey, priorHead: 'aa'.repeat(32),
    from: jo.publicKey, to: jo.publicKey, at: 1_711_000_000_001,
  }));
  assert.deepEqual(verifyAnchorHop(jo_anchor, [item.publicKey]), { ok: false, reason: 'anchor-unregistered' });
  const forged = { ...restart, sigs: { [item.publicKey]: restart.sigs[item.publicKey] } };
  delete forged.body;
  assert.deepEqual(verifyAnchorHop(forged, [item.publicKey]), { ok: false, reason: 'signature' });
  // a flip is not an anchor, whatever it signs
  const flip = signHop([maria.secretKey, jo.secretKey], hopBody({
    kind: 'flip', itemKey: item.publicKey, priorHead: 'bb'.repeat(32),
    from: maria.publicKey, to: jo.publicKey, at: 1_711_000_000_002,
  }));
  assert.deepEqual(verifyAnchorHop(flip, [jo.publicKey]), { ok: false, reason: 'not-anchor' });
});
