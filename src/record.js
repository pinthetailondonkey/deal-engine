import { canonicalBytes, bytesToHex, H } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';
import { normalizeAmount } from './units.js';

// Deal records: the co-signed object two parties hold. Rules driven by the
// attack reports:
// - role comes from key match, never a self-declared string
// - buyer === vendor is refused at the byte level
// - amounts are decimal strings only
// - public views carry no money amount, ever, in any form (docs/proof-of-trade.md)

export const RECORD_TAG = 'Deal record v1';

export function recordBody(input = {}) {
  return {
    v: 1,
    dealId: String(input.dealId || ''),
    vendor: String(input.vendor || '').toLowerCase(),
    buyer: String(input.buyer || '').toLowerCase(),
    title: String(input.title || ''),
    claim: String(input.claim || ''),
    currency: String(input.currency || '').toLowerCase(),
    amount: input.amount == null || input.amount === '' ? '' : normalizeAmount(input.amount),
    at: requireAt(input.at),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The record needs a time.');
  return value;
}

export function recordHash(body) {
  return bytesToHex(H(RECORD_TAG, canonicalBytes(body)));
}

export function recordBytes(body) {
  return canonicalBytes(body);
}

export function signRecord(secretKey, body, prior = null) {
  const canonicalBody = recordBody(body);
  if (canonicalBody.buyer === canonicalBody.vendor || !canonicalBody.buyer) {
    throw new Error('A deal needs a buyer different from the vendor.');
  }
  const message = recordBytes(canonicalBody);
  const pub = publicKeyOf(secretKey);
  const role = pub === canonicalBody.buyer ? 'buyer'
    : pub === canonicalBody.vendor ? 'vendor' : '';
  if (!role) throw new Error('That key is neither the buyer nor the vendor.');
  if (prior?.hash && prior.hash !== recordHash(canonicalBody)) {
    throw new Error('The co-signature is over a different record.');
  }
  const sigs = { ...(prior?.sigs || {}) };
  sigs[role] = sign(secretKey, message);
  return { v: 1, tag: RECORD_TAG, hash: recordHash(canonicalBody), body: canonicalBody, sigs };
}

export function coSignRecord(signed, secretKey) {
  if (verifyRecord(signed)) return signed;
  return signRecord(secretKey, signed?.body, signed);
}

export function verifyRecord(signed) {
  try {
    if (!signed?.body || !signed?.sigs?.buyer || !signed?.sigs?.vendor) return false;
    if (signed.tag !== RECORD_TAG) return false;
    const body = recordBody(signed.body);
    const message = recordBytes(body);
    if (bytesToHex(H(RECORD_TAG, canonicalBytes(body))) !== signed.hash) return false;
    if (body.buyer === body.vendor || !body.buyer || !body.vendor) return false;
    const buyerOk = verify(signed.sigs.buyer, message, body.buyer);
    const vendorOk = verify(signed.sigs.vendor, message, body.vendor);
    return buyerOk && vendorOk;
  } catch {
    return false;
  }
}

// void statements: a refunded or undone deal never decrements any count —
// it becomes a visible, signed entry on a ledger beside the count.
export const VOID_TAG = 'Deal void v1';

export function signVoid(secretKey, signedRecord, reason, at) {
  if (!signedRecord?.hash || !verifyRecord(signedRecord)) throw new Error('Void needs a valid record.');
  const body = {
    v: 1,
    voids: signedRecord.hash,
    reason: String(reason || ''),
    at: requireAt(at),
  };
  const pub = publicKeyOf(secretKey);
  const role = pub === signedRecord.body.buyer ? 'buyer'
    : pub === signedRecord.body.vendor ? 'vendor' : '';
  if (!role) throw new Error('That key is not a party to this record.');
  return {
    v: 1,
    tag: VOID_TAG,
    hash: bytesToHex(H(VOID_TAG, canonicalBytes(body))),
    body,
    sigs: { [role]: sign(secretKey, canonicalBytes(body)) },
  };
}

export function verifyVoid(signedRecord, voided) {
  try {
    if (!signedRecord || !voided?.body || !voided?.sigs) return false;
    if (voided.tag !== VOID_TAG || voided.body.voids !== signedRecord.hash) return false;
    if (!verifyRecord(signedRecord)) return false;
    const entries = Object.entries(voided.sigs);
    if (entries.length !== 1) return false;
    const [role, sig] = entries[0];
    return verify(sig, canonicalBytes(voided.body), signedRecord.body[role] || '');
  } catch {
    return false;
  }
}
