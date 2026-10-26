import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import {
  signCheckpoint, keyIdOf, verifyCheckpoint,
} from '../src/checkpoint.js';
import { makeTree } from '../src/merkle.js';
import { verifyConsistencyProof, consistencyHolds } from '../src/merkle.js';
import { encodeParts, bytesToHex, H } from '../src/canonical.js';
import { bytesHex } from './helpers.js';
import { verifyBlindMembership } from '../src/accumulator.js';

const t0 = 1_700_000_000_000;
const vendor = generateKey();
const w = generateKey();

function stc(over = {}) {
  const size = over.treeSize ?? 3;
  return signCheckpoint(vendor.secretKey, {
    seq: over.seq ?? 1,
    treeSize: size,
    root: over.root ?? bytesHex(makeTree(Array.from({ length: size }, (_, i) => encodeParts(['s', String(i)]))).mthAll()),
    prevHead: over.prevHead ?? '',
    issuedAt: over.at ?? t0,
    keyId: keyIdOf(vendor.publicKey),
    witnessRegistry: over.registry ?? [w.publicKey],
    accN: over.accN ?? '',
    accRoot: over.accRoot ?? '',
  });
}

test('shape: a checkpoint that commits to nothing cannot exist', () => {
  for (const bad of ['', 'ff'.repeat(31), 'ff'.repeat(33), 'ZZ'.repeat(32), 'g'.repeat(64)]) {
    assert.throws(() => stc({ root: bad }), /64-hex/, `root ${JSON.stringify(bad)} is refused`);
  }
  // the empty-root STC from the attack (t7) — it used to verify and stand
  const empty = {
    v: 1, tag: 'Deal checkpoint v1',
    body: { v: 1, seq: 1, treeSize: 8888888, root: '', prevHead: '', issuedAt: t0, keyId: keyIdOf(vendor.publicKey), witnessRegistry: '', accN: '', accRoot: '' },
    key: vendor.publicKey, sig: 'ff'.repeat(64), head: 'ab'.repeat(32),
  };
  assert.equal(verifyCheckpoint(empty), false, 'an empty-root checkpoint verifies as nothing');
});

test('shape: degenerate accumulator fields are refused at the body door', () => {
  assert.throws(() => stc({ accRoot: '01' }), /accumulator root/);
  assert.throws(() => stc({ accRoot: 'zz' }), /accumulator root/);
  assert.throws(() => stc({ accN: '1' }), /modulus is hex bytes/);
  // honest shapes still enter
  const ok = stc({ accN: 'ab'.repeat(256), accRoot: 'cd'.repeat(32) });
  assert.equal(verifyCheckpoint(ok), true);
});

test('shape: the blind membership check refuses degenerate commitments', () => {
  // e=0 (element '00') makes witness^0 = 1 = any degenerate root
  assert.equal(verifyBlindMembership({ root: '01', n: 'ab'.repeat(128) }, '00', '07'), false,
    'root 1 with element 0 is the forged shape from the attack');
  assert.equal(verifyBlindMembership({ root: '00', n: 'ab'.repeat(128) }, '05', '07'), false, 'root 0 commits to nothing');
  assert.equal(verifyBlindMembership({ root: '01', n: 'ab'.repeat(128) }, '0b', '01'), false, 'witness 1 against root 1 is not membership');
  // a sane element is also required: e must exceed 1
  const realRoot = bytesToHex(H('shape test', 'x'));
  assert.equal(verifyBlindMembership({ root: realRoot, n: 'ab'.repeat(128) }, '01', '02'), false);
});

test('shape: identical trees still pose two REAL roots for consistency', () => {
  assert.equal(consistencyHolds(3, 3, [], '', ''), false, 'two empty strings are no commitment');
  const root = bytesHex(makeTree(Array.from({ length: 3 }, (_, i) => encodeParts(['s', String(i)]))).mthAll());
  assert.equal(verifyConsistencyProof(3, 3, [], root, root), true);
});
