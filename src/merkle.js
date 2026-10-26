import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from './canonical.js';

// RFC 6962 Merkle tree, adopted untouched: the log-crypto attacker's call.
// CHAR-0x00 prefix on leaves, 0x01 on interior nodes, domain-separated keep
// leaf-as-interior replay impossible, and consistency proofs make
// "extends prior" a mathematical check, not a social claim with a checkmark.
//
// Deviation from the RFC, stated because it matters for interop (PoT v2):
// the tree follows RFC 6962's hashing and MTH shape, but its consistency
// proofs and verifier are this module's own and are NOT byte-compatible
// with a Certificate-Transparency implementation. RFC 6962 §2.1.2 derives
// the proof path differently for some (m, n) splits; this verifier accepts
// this module's own proof shape only (and an m = n pair only as the empty
// proof with identical roots). It is self-consistent — every (m, n) grid
// position is pinned in merkle.test.js — but a proof produced here will be
// rejected by a CT verifier and vice versa. If PoT v2 ever needs to
// interoperate with real CT logs, this module is the one that changes.

const EMPTY_ROOT = sha256(new Uint8Array(0)); // SHA-256 of nothing, per RFC 6962

function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// leaves: array of Uint8Array (the raw, pre-prefixed leaf bytes)
export function leafHash(leafBytes) {
  const prefix = new Uint8Array(1); // 0x00
  return sha256(concatBytes([prefix, leafBytes]));
}

// memoized per-tree: leafHashes cached on the tree object
export function makeTree(leafBytesList) {
  const leaves = (leafBytesList || []).map(leafHash);
  const cache = new Map();
  const mth = (start, end) => {
    const key = `${start}:${end}`;
    const hit = cache.get(key);
    if (hit) return hit;
    const n = end - start;
    let out;
    if (n === 0) out = EMPTY_ROOT;
    else if (n === 1) out = leaves[start];
    else {
      const k = largestPowerOfTwoBelow(n);
      const prefix = new Uint8Array(1);
      prefix[0] = 0x01;
      out = sha256(concatBytes([prefix, mth(start, start + k), mth(start + k, end)]));
    }
    cache.set(key, out);
    return out;
  };
  return {
    size: leaves.length,
    mthAll: () => mth(0, leaves.length),
    mthRange: (start, end) => mth(start, end),

    // RFC 6962 §2.1.1
    inclusionProof(index) {
      if (index < 0 || index >= leaves.length) throw new Error('No such leaf.');
      const path = [];
      const walk = (start, end) => {
        const n = end - start;
        if (n === 1) return leaves[start];
        const k = largestPowerOfTwoBelow(n);
        if (index < start + k) {
          const left = walk(start, start + k);
          path.push(mth(start + k, end));
          return left;
        }
        const right = walk(start + k, end);
        path.push(mth(start, start + k));
        return right;
      };
      walk(0, leaves.length);
      return path;
    },

    // RFC 6962 §2.1.2: proof that the first `m` leaves are a prefix of the
    // `n`-leaf tree whose root is returned. Only the first-m sub-hashes the
    // verifier already holds are rebuilt; the rest come from the proof.
    consistencyProof(m) {
      const n = leaves.length;
      if (m === n) return [];
      if (m < 1 || m > n) throw new Error('Bad consistency size.');
      const out = [];
      const emit = (start, end) => out.push(mth(start, end));
      const walk = (start, end, localM, isFirst) => {
        // isFirst: this subtree IS the first-m tree when localM === subSize
        const nSub = end - start;
        if (localM === nSub) {
          // the boundary subtree's root is the verifier's own rootm; emit
          // nothing, but callers below may need it as a sibling.
          if (!isFirst) emit(start, end);
          return;
        }
        const k = largestPowerOfTwoBelow(nSub);
        if (localM <= k) {
          // subtree entirely inside the first-m region
          walk(start, start + k, localM, isFirst ? true : false);
          // right sibling is NOT part of first-m — supply it
          emit(start + k, end);
        } else {
          walk(start + k, end, localM - k, false);
          emit(start, start + k);
        }
      };
      walk(0, n, m, true);
      return out;
    },
  };
}

export function verifyInclusionProof(leafBytes, index, treeSize, proof, rootHex) {
  try {
    if (index < 0 || index >= treeSize || treeSize < 1) return false;
    // Mirror the generator's skeleton recursively and fold bottom-up: the
    // innermost call runs first and takes the FRONT proof element, matching
    // inclusionProof()'s deepest-sibling-first emission order.
    const stack = [...proof];
    const leaf = leafHash(leafBytes);
    const rec = (lo, n) => {
      if (n === 1) return leaf; // only reached on the leaf's own subtree
      const k = largestPowerOfTwoBelow(n);
      const prefix = new Uint8Array(1);
      prefix[0] = 0x01;
      if (lo < k) {
        const sub = rec(lo, k);
        const sib = stack.shift();
        return sha256(concatBytes([prefix, sub, sib]));
      }
      // inner call first: it consumes the deeper proof element
      const sub = rec(lo - k, n - k);
      const sib = stack.shift();
      return sha256(concatBytes([prefix, sib, sub]));
    };
    const root = rec(index, treeSize);
    if (stack.length !== 0) return false;
    return bytesEqHex(root, rootHex);
  } catch {
    return false;
  }
}

export function verifyConsistencyProof(m, n, proof, firstRootHex, secondRootHex) {
  try {
    // identical trees still pose two REAL roots (attack round two, finding
    // 3): two empty strings are not roots, they are no commitment at all.
    if (m === n) {
      return proof.length === 0
        && /^[0-9a-f]{64}$/.test(firstRootHex)
        && firstRootHex === secondRootHex;
    }
    if (m < 1 || m > n) return false;
    let hashM = hexToBytesF(firstRootHex);
    let hashN = hexToBytesF(secondRootHex);
    const prefix = new Uint8Array(1);
    prefix[0] = 0x01;
    // Mirror the generator's skeleton recursively. The proof list is emitted
    // deepest-first (inner walk pushes before the outer sibling), and the
    // innermost rec call runs first, so it consumes from the FRONT.
    // Each rec call returns [firstRoot, secondRoot] for its subtree; firstRoot
    // is only meaningful when the child on the boundary side is fully known:
    // an entirely-first subtree that IS the first-m tree folds from hashM
    // (isFirst true all the way means the walk never left the prefix side),
    // while one reached through a right branch is supplied by the proof.
    const stack = [...proof];
    const rec = (localM, len, isFirst) => {
      if (localM === len) {
        if (isFirst) return [hashM, hashM];
        const emitted = stack.shift();
        return [emitted, emitted];
      }
      const k = largestPowerOfTwoBelow(len);
      if (localM <= k) {
        // boundary inside the left subtree; right sibling is second-tree only
        const [lM, lN] = rec(localM, k, isFirst);
        const sibling = stack.shift();
        return [lM, sha256(concatBytes([prefix, lN, sibling]))];
      }
      // boundary inside the right subtree; left sibling is fully first-tree
      const [rM, rN] = rec(localM - k, len - k, false);
      const sibling = stack.shift();
      return [
        sha256(concatBytes([prefix, sibling, rM])),
        sha256(concatBytes([prefix, sibling, rN])),
      ];
    };
    const [outM, outN] = rec(m, n, true);
    if (stack.length !== 0) return false;
    return bytesEqHex(outN, secondRootHex) && bytesEqHex(outM, firstRootHex);
  } catch {
    return false;
  }
}

// RFC 6962 §2.1.2 verification. firstRootHex is what the earlier checkpoint
// claimed; secondRootHex the later one. Returns true only if the sequence
// actually extends.
export function consistencyHolds(m, n, proof, firstRootHex, secondRootHex) {
  return verifyConsistencyProof(m, n, proof, firstRootHex, secondRootHex);
}

function bytesEqHex(bytes, hex) {
  return bytesToHexLocal(bytes) === String(hex || '').toLowerCase();
}

function bytesToHexLocal(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function hexToBytesF(hex) {
  const text = String(hex || '');
  if (text.length === 0) return new Uint8Array(0);
  if (text.length % 2) throw new Error('Not hex.');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}
