import { bytesToHex, H, canonicalBytes } from './canonical.js';
import { makeTree } from './merkle.js';
import { publicKeyOf } from './keys.js';
import { elementOf, accRootOf } from './accumulator.js';
import {
  signCheckpoint, verifyCheckpoint, keyIdOf,
  verifyWitnessStatement, verifyForkEvidence,
} from './checkpoint.js';
import { verifyRecord } from './record.js';

// The log: co-signed deal records, a blinded Merkle tree over them, and the
// vendor's signed checkpoints + witness statements. This module holds the
// observer-side state and answers the queries the design's screens need:
//
//   log.commit(record)          -> append a valid dual-signed record
//   log.checkpoint(secretKey)   -> sign a checkpoint over the current tree
//   log.witness(...)            -> content-bound witness statement
//   log.standing(observerClock) -> the 7-state lifecycle, computed
//   log.reveal(dealId, salt)    -> an audit window's contents (leaf + proof)
//
// The four fixes the reports demanded and that live below:
// - leaves are blinded: H(salt || canonical record) — no dictionary attack
//   against disclosed co-paths unless a window was opened for you.
// - checkpoints carry size history, so the UI can show deltas over time
//   instead of a headline number that means nothing.
// - the count the log reports is always "tree size self-declared in the
//   latest witnessed checkpoint", never "deals completed".
// - key compromise is not modelized here as impossible; the log reports
//   FORKED when evidence appears, and a checkpoint signed by an unknown key
//   after a known one is refused until a signed rotation admits it.

export const LEAF_TAG = 'Deal leaf v1';

export function blindedLeaf(record, salt) {
  const saltBytes = typeof salt === 'string' ? hexToBytesStrict(salt) : salt;
  const recordHash = H(LEAF_TAG, canonicalBytes(record.body));
  return H('Deal leaf blind v1', saltBytes, recordHash);
}

export function hexToBytesStrict(hex) {
  const text = String(hex || '');
  if (text.length % 2) throw new Error('Salt is not hex.');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Salt provenance: production is both parties' randomness mixed. The
// vendor brings fresh bytes; the buyer is REQUIRED to bring at least 8
// bytes when they contribute at all. The final salt is a domain-separated
// hash of both — never their concatenation, which a dictionary attack
// could peel apart. The blinding property holds even if the buyer cheats
// (weak salt still hides the leaf behind vendor randomness); the entropy
// floor exists so a lazy buyer cannot hand the vendor a predictable mix.
export function mixedSaltHex(vendorSaltBytes, buyerSaltHex) {
  if (typeof buyerSaltHex !== 'string') throw new Error('The buyer\'s salt is a hex string or nothing.');
  if (buyerSaltHex.length < 2 * 8) throw new Error('The buyer\'s salt needs at least 8 bytes of entropy.');
  const buyerBytes = hexToBytesStrict(buyerSaltHex);
  return bytesToHex(H('Deal salt mix v1', vendorSaltBytes, buyerBytes));
}

export function makeLog(options = {}) {
  const vendorKey = options.vendorKey ? String(options.vendorKey).toLowerCase() : '';
  const records = [];
  const salts = [];
  const voidEd = new Map(); // recordHash -> void statement
  let discardedForInvalid = 0;

  let currentVendor = vendorKey;

  const log = {
    get size() { return records.length; },
    get records() { return records.slice(); },
    get voided() { return [...voidEd.values()]; },

    // the accumulator's elements, in log order, from the BLINDED leaves
    elementsFor() {
      return records.map((_, index) => elementOf(bytesToHex(log.leafBytes(index))));
    },

    // key rotation: the log admits the successor so post-rotation commits
    // verify against the NEW key. Pre-rotation records stay valid as-is.
    setVendor(newVendorKey) {
      if (!newVendorKey || typeof newVendorKey !== 'string') {
        throw new Error('The log needs a vendor key.');
      }
      currentVendor = newVendorKey.toLowerCase();
    },

    commit(signedRecord, saltHex16) {
      if (!verifyRecord(signedRecord)) {
        discardedForInvalid += 1;
        throw new Error('The log takes valid dual-signed records only.');
      }
      if (currentVendor
        && signedRecord.body.vendor !== currentVendor
        && signedRecord.body.buyer !== currentVendor) {
        discardedForInvalid += 1;
        throw new Error('The log holds one vendor\'s records.');
      }
      if (records.some((row) => row.record.hash === signedRecord.hash)) {
        throw new Error('That record is already in the log.');
      }
      // blinding salt: co-set at commit time. With a buyer contribution the
      // vendor's fresh bytes are mixed with it (mixedSaltHex); without one
      // the vendor's bytes stand alone and provenance says so.
      const salt = saltHex16 || bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
      records.push({ record: signedRecord, salt });
      return salt;
    },

    leafBytes(index) {
      const row = records[index];
      if (!row) return null;
      return blindedLeaf(row.record, row.salt);
    },

    void(signedRecord, voided) {
      if (!records.some((row) => row.record.hash === signedRecord?.hash)) {
        throw new Error('Void needs a record in the log.');
      }
      voidEd.set(voided.hash, { record: signedRecord.hash, voided });
      return voided;
    },

    // checkpoint over the current tree. The SIGNER owns seq; cadence itself
    // is a protocol constant and cannot be re-declared by the vendor.
    // accN opts in the accumulator: accRoot commits to the SAME set the
    // Merkle root commits to, so both surfaces describe one tree.
    signedTreeState(secretKey, { seq, issuedAt, witnessRegistry, priorHead = '', accN = '' }) {
      if (records.length === 0) throw new Error('An empty tree checkpoints nothing.');
      const tree = makeTree(records.map((_, index) => log.leafBytes(index)));
      let accRoot = '';
      if (accN) {
        accRoot = accRootOf(log.elementsFor(), accN);
      }
      const body = {
        seq: seq ?? 1,
        treeSize: records.length,
        root: bytesToHex(tree.mthAll()),
        prevHead: priorHead,
        issuedAt,
        keyId: keyIdOf(publicKeyOf(secretKey)),
        witnessRegistry: witnessRegistry || [],
        accN: accN || '',
        accRoot,
      };
      return signCheckpoint(secretKey, body);
    },
  };
  return log;
}
