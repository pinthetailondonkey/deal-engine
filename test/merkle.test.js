import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2.js';
import { makeTree, verifyInclusionProof, verifyConsistencyProof, leafHash } from '../src/merkle.js';
import { encodeParts, concatBytes } from '../src/canonical.js';

function leaves(n) {
  return Array.from({ length: n }, (_, i) => encodeParts(['leaf', String(i)]));
}

test('merkle: known leaf verifies, tampered leaf does not', () => {
  const tree = makeTree(leaves(8));
  for (let i = 0; i < 8; i += 1) {
    const proof = tree.inclusionProof(i);
    assert.equal(verifyInclusionProof(leaves(8)[i], i, 8, proof, bytes(tree.mthAll())), true);
  }
  assert.equal(verifyInclusionProof(leaves(8)[0], 0, 8, tree.inclusionProof(0), '00'.repeat(32)), false);
});

function bytes(u8) {
  let out = '';
  for (const b of u8) out += b.toString(16).padStart(2, '0');
  return out;
}

function nodeHash(a, b) {
  const prefix = new Uint8Array(1);
  prefix[0] = 0x01;
  return sha256(concatBytes([prefix, a, b]));
}

test('merkle: RFC 6962 shapes — the 3-leaf tree is the CT skeleton, not a Bitcoin tree', () => {
  const tree = makeTree(leaves(3));
  // k splits at 2: root = H01( H01(leaf0, leaf1), leaf2 ) — a promoted-single
  // tree would instead be H01(leaf0, H01(leaf1, leaf2)). The design must be
  // the CT tree: consistency proofs depend on the split structure.
  const manual = nodeHash(nodeHash(leafHash(leaves(3)[0]), leafHash(leaves(3)[1])), leafHash(leaves(3)[2]));
  assert.equal(bytes(tree.mthAll()), bytes(manual));
});

test('merkle: brute-force inclusion proofs for every size and index', () => {
  for (let n = 1; n <= 33; n += 1) {
    const tree = makeTree(leaves(n));
    const root = bytes(tree.mthAll());
    for (let i = 0; i < n; i += 1) {
      const ok = verifyInclusionProof(leaves(n)[i], i, n, tree.inclusionProof(i), root);
      if (!ok) assert.fail(`inclusion failed for n=${n} index=${i}`);
    }
  }
});

test('merkle: brute-force consistency proofs, m × n grid', () => {
  for (let n = 2; n <= 32; n += 1) {
    const tree = makeTree(leaves(n));
    const rootN = bytes(tree.mthAll());
    for (let m = 1; m <= n; m += 1) {
      const rootM = bytes(makeTree(leaves(m)).mthAll());
      const proof = tree.consistencyProof(m);
      const ok = verifyConsistencyProof(m, n, proof, rootM, rootN);
      if (!ok) assert.fail(`consistency failed for m=${m} n=${n}`);
    }
  }
});

test('merkle: a forged consistency proof fails (dropped one hash)', () => {
  const tree = makeTree(leaves(16));
  const proof = tree.consistencyProof(10);
  const short = proof.slice(0, proof.length - 1);
  const rootM = bytes(makeTree(leaves(10)).mthAll());
  assert.equal(verifyConsistencyProof(10, 16, short, rootM, bytes(tree.mthAll())), false);
});

test('merkle: proof reorders do not verify', () => {
  const tree = makeTree(leaves(12));
  const proof = tree.inclusionProof(5);
  const swapped = [proof[1], proof[0], ...proof.slice(2)];
  assert.equal(
    verifyInclusionProof(leaves(12)[5], 5, 12, swapped, bytes(tree.mthAll())),
    false,
  );
});
