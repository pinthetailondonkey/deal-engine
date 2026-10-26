import { bytesToHex, H, canonicalBytes } from './canonical.js';
import { makeTree } from './merkle.js';
import { publicKeyOf } from './keys.js';
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

function hexToBytesStrict(hex) {
  const text = String(hex || '');
  if (text.length % 2) throw new Error('Salt is not hex.');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function makeLog(options = {}) {
  const vendorKey = options.vendorKey ? String(options.vendorKey).toLowerCase() : '';
  const records = [];
  const salts = [];
  const voidEd = new Map(); // recordHash -> void statement
  let discardedForInvalid = 0;

  const log = {
    get size() { return records.length; },
    get records() { return records.slice(); },
    get voided() { return [...voidEd.values()]; },

    commit(signedRecord, saltHex16) {
      if (!verifyRecord(signedRecord)) {
        discardedForInvalid += 1;
        throw new Error('The log takes valid dual-signed records only.');
      }
      if (vendorKey
        && signedRecord.body.vendor !== vendorKey
        && signedRecord.body.buyer !== vendorKey) {
        discardedForInvalid += 1;
        throw new Error('The log holds one vendor\'s records.');
      }
      if (records.some((row) => row.record.hash === signedRecord.hash)) {
        throw new Error('That record is already in the log.');
      }
      // blinding salt: co-set at commit time. Real deployment: both parties
      // contribute randomness; the engine sets one here and stores it so a
      // window can open.
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
    signedTreeState(secretKey, { seq, issuedAt, witnessRegistry, priorHead = '' }) {
      if (records.length === 0) throw new Error('An empty tree checkpoints nothing.');
      const tree = makeTree(records.map((_, index) => log.leafBytes(index)));
      const body = {
        seq: seq ?? 1,
        treeSize: records.length,
        root: bytesToHex(tree.mthAll()),
        prevHead: priorHead,
        issuedAt,
        keyId: keyIdOf(publicKeyOf(secretKey)),
        witnessRegistry: witnessRegistry || [],
      };
      return signCheckpoint(secretKey, body);
    },
  };
  return log;
}
