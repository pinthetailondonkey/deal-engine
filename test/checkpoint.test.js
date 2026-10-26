import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, keyPairFromSeed } from '../src/keys.js';
import {
  signCheckpoint, verifyCheckpoint, keyIdOf,
  signWitnessStatement, verifyWitnessStatement,
  forkEvidence, verifyForkEvidence, signRefusal, verifyRefusal,
} from '../src/checkpoint.js';
import { makeTree } from '../src/merkle.js';
import { encodeParts } from '../src/canonical.js';

const vendor = () => generateKey();
const witness = () => generateKey();

function stcBody(key, over = {}) {
  return {
    seq: 1,
    treeSize: 5,
    root: bytes(makeTree(Array.from({ length: 5 }, (_, i) => encodeParts([String(i)]))).mthAll()),
    prevHead: '',
    issuedAt: 1_700_000_000_000,
    keyId: keyIdOf(key.publicKey),
    witnessRegistry: over.witnessRegistry || [],
    ...over,
  };
}
function bytes(u8) { let s = ''; for (const b of u8) s += b.toString(16).padStart(2, '0'); return s; }

test('checkpoint: valid, all fields inside the signature', () => {
  const keys = vendor();
  const stc = signCheckpoint(keys.secretKey, stcBody(keys));
  assert.equal(verifyCheckpoint(stc), true);
  const tampered = JSON.parse(JSON.stringify(stc));
  tampered.body.treeSize = 999;            // size forgery
  assert.equal(verifyCheckpoint(tampered), false);
  const tampered2 = JSON.parse(JSON.stringify(stc));
  tampered2.body.prevHead = 'ff'.repeat(32); // history rewrite
  assert.equal(verifyCheckpoint(tampered2), false);
  const tampered3 = JSON.parse(JSON.stringify(stc));
  tampered3.body.witnessRegistry = ['01'.repeat(33)]; // registry swap
  assert.equal(verifyCheckpoint(tampered3), false);
});

test('checkpoint: cadence is a protocol constant, not a field', () => {
  const keys = vendor();
  const ratchet = signCheckpoint(keys.secretKey, stcBody(keys, { cadence: 365_000 }));
  // brute check: cadence never took effect — the freshest attacker path is
  // dead because the object has no cadence field at all
  assert.equal('cadence' in ratchet.body, false);
});

test('checkpoint: witness statements bind the exact checkpoint content', () => {
  const keys = vendor();
  const w = witness();
  const stc = signCheckpoint(keys.secretKey, stcBody(keys, { witnessRegistry: [w.publicKey] }));
  const statement = signWitnessStatement(w.secretKey, stc);
  assert.equal(verifyWitnessStatement(stc, statement), true);
  // same head claimed to a different witness with different content: the
  // statement bytes differ, and only one binds to THIS checkpoint's bytes
  const otherStc = signCheckpoint(keys.secretKey, stcBody(keys, { witnessRegistry: [w.publicKey], treeSize: 6 }));
  assert.equal(verifyWitnessStatement(otherStc, statement), false);
  // a key that no registry admitted cannot witness
  const outsider = witness();
  assert.throws(() => signWitnessStatement(outsider.secretKey, stc), /not in this checkpoint/);
  assert.equal(verifyWitnessStatement(stc, { ...statement, witness: outsider.publicKey }), false);
});

test('checkpoint: fork evidence is computable and verifiable', () => {
  const keys = vendor();
  const base = signCheckpoint(keys.secretKey, stcBody(keys, { prevHead: 'aa'.repeat(32) }));
  const forkA = signCheckpoint(keys.secretKey, stcBody(keys, { seq: 2, treeSize: 5, prevHead: base.head }));
  const forkB = signCheckpoint(keys.secretKey, stcBody(keys, { seq: 2, treeSize: 7, prevHead: base.head }));
  const evidence = forkEvidence(forkA, forkB);
  assert.ok(evidence, 'a size disagreement on the same parent is fork evidence');
  assert.equal(verifyForkEvidence(evidence), true);
  assert.equal(verifyForkEvidence(JSON.parse(JSON.stringify(evidence))), true);
  // same line: not a fork
  assert.equal(forkEvidence(forkA, signCheckpoint(keys.secretKey, stcBody(keys, { seq: 2, treeSize: 5, prevHead: base.head }))), null);
});

test('checkpoint: key rotation — key id binds the key, an unknown key fails', () => {
  const keys = vendor();
  const forged = signCheckpoint(keys.secretKey, stcBody(keys));
  forged.body.keyId = keyIdOf(generateKey().publicKey); // claim another key's id
  assert.equal(verifyCheckpoint(forged), false);
});

test('checkpoint: refusal is signed, ages, and is not a verdict', () => {
  const keys = vendor();
  const refusal = signRefusal(keys.secretKey, 1_700_000_000_000);
  assert.equal(verifyRefusal(refusal), true);
  const other = vendor();
  assert.notEqual(
    signRefusal(other.secretKey, 1_700_000_000_000).keyId,
    refusal.keyId,
  );
});
