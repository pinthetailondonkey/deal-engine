import { bytesToHex, H, canonicalBytes } from './canonical.js';
import { sign, verify, publicKeyOf, deriveItemKey } from './keys.js';

// Title chains: per-item custody. What the attack reports forced the design
// to keep, and what they forced it to change:
// - keys are per-item derived, so holding two titles never cross-links.
// - a hop is dual-signed by whoever had it and whoever got it.
// - disputes attach to a hop and RESOLVE through the same machinery as
//   money disputes — no permanent unresolved badge.
// - a truncation is a lineage break, not a badge: the chain must show its
//   new root as the child of a truncation record.
// - the engine does not anchor the item to the physical world. An anchor is
//   an external attestation the engine records and requires, never an
//   engine-computed truth. Honest limitation, stated in the code that would
//   otherwise hide it.
// - ANCHOR ATTESTATION IS HARD-GATED NOW (closes the old hole): an anchor
//   hop only verifies inside a chain when the READER holds an admitted
//   registry key set (opts.anchorKeys) and the anchor's signing key is in
//   it. A chain carrying an anchor that arrives with no registry — a bad
//   one, an empty one, a malformed one — refuses outright, never a silent
//   pass. The self-anchored restart hop is an anchor kind: it always
//   requires the registry. What the gate does NOT change: the signature
//   rule (requiredSignersFor: 'to' signs) proves still only that the key
//   accepted the hop — it does NOT prove the registry's out-of-band check
//   was performed. The engine closes the verification hole (an unadmitted
//   key can no longer pass an anchor off as verified); the attestation's
//   real strength remains the registry's own procedure, outside this code.

export const HOP_TAG = 'Title hop v1';
export const DISPUTE_ATTACH_TAG = 'Title dispute attach v1';

export function itemKeyPair(masterSecretKey, itemId) {
  // per-item key is derived in keys.js: the master SECRET goes inside a
  // domain-separated hash with the item id, so the child is not an affine
  // offset of the master — no public relation links them, and a leaked item
  // secret recovers nothing. One derivation site total (attack round two):
  // title.js and keys.js previously kept separate schemes, which was itself
  // a bug waiting on a caller who mixes them.
  return deriveItemKey(masterSecretKey, itemId);
}

export function hopBody(input = {}) {
  return {
    v: 1,
    kind: ['born', 'flip', 'anchor', 'truncation'].includes(input.kind) ? input.kind : '',
    itemKey: String(input.itemKey || '').toLowerCase(),
    priorHead: String(input.priorHead || ''),
    from: String(input.from || '').toLowerCase(),
    to: String(input.to || '').toLowerCase(),
    at: requireAt(input.at),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The hop needs a time.');
  return value;
}

export function hopHash(body) {
  return bytesToHex(H(HOP_TAG, canonicalBytes(body)));
}

// Dual signatures: born is attested+received; flip is given+received;
// anchor admits a registry key; truncation is the VENDOR's own statement
// that history before a point is lost — it STARTS a lineage, never extends
// an old one wearing a new name. Only the item key's DERIVER (the vendor
// whose master secret produces this itemKey) may truncate; a truncation
// signed by anyone else is a forgery, not a break (attack round three,
// protocol P2: any observer could graft a self-signed truncation onto an
// honest chain and inherit custody through it).
export function signHop(secretKeys, body) {
  const canonicalBody = hopBody(body);
  if (!canonicalBody.kind) throw new Error('Not a hop kind.');
  if (canonicalBody.kind === 'flip' && canonicalBody.from === canonicalBody.to) {
    throw new Error('A flip that goes nowhere flips nothing.');
  }
  const sigs = {};
  for (const secretKey of [].concat(secretKeys)) {
    sigs[publicKeyOf(secretKey)] = sign(secretKey, canonicalBytes(canonicalBody));
  }
  const required = requiredSignersFor(canonicalBody);
  for (const role of required) {
    if (!sigs[canonicalBody[role]]) throw new Error(`The ${role} key must sign the hop.`);
  }
  return { v: 1, tag: HOP_TAG, hash: hopHash(canonicalBody), body: canonicalBody, sigs };
}

function requiredSignersFor(body) {
  if (body.kind === 'born') return ['from', 'to'];
  if (body.kind === 'flip') return ['from', 'to'];
  if (body.kind === 'anchor') return ['to'];
  return ['from']; // truncation: the holder attests the break alone
}

export function verifyHopChain(hops, opts = {}) {
  // cross-item blinding means the verifier checks hop-key consistency and
  // signer validity, not re-derivation: the same holder showing two chains
  // reveals no shared key.
  //
  // Attack round two (protocol F12, API F2): the verifier authenticated
  // nothing. Now it also enforces: a chain exists only when its first hop
  // is a born hop with no parent or a truncation (a flip with an empty
  // priorHead used to root itself); custody never jumps (next.from must be
  // prev.to); and the itemKey is constant along the lineage. A null entry
  // degrades to not-verified instead of crashing the honest verifier.
  //
  // Attack round three (protocol P2): the truncation EXEMPTION was the
  // bypass — any observer grafted a self-signed truncation onto an honest
  // tip and inherited custody through it, and the hop after a truncation
  // started from any stranger. A truncation is now signed by the ITEM KEY
  // ITSELF (from === itemKey): only the deriver's master secret can produce
  // that key, so the break is self-proving and no verifier needs the
  // master. The custody rule then applies with NO truncation exemptions —
  // the break's holder is the item key, and custody resumes only from it.
  let tip = null;
  const sorted = [...(hops || [])].sort((a, b) => (a?.body?.at ?? 0) - (b?.body?.at ?? 0));
  // ANCHOR GATE: any anchor in the chain demands the reader's own registry.
  // Empty array = registered-but-refuses-all: loud, never a silent pass.
  // A non-array (or junk hex inside) refuses the same way — an anchor
  // chain never downgrades to keyless verification on a reader's mistake.
  // (The self-anchored restart IS an anchor kind: born chains stay
  // registry-free; the gate bites exactly where an attestation exists.)
  const hasAnchor = sorted.some((hop) => hop?.body?.kind === 'anchor');
  if (hasAnchor) {
    if (!(opts.anchorKeys instanceof Array)) return { ok: false, reason: 'anchor-unregistered' };
    if (!opts.anchorKeys.every((key) => typeof key === 'string' && /^[0-9a-f]{64}$/.test(key.toLowerCase()))) {
      return { ok: false, reason: 'anchor-unregistered' };
    }
    const admitted = new Set(opts.anchorKeys.map((key) => key.toLowerCase()));
    for (const hop of sorted) {
      if (hop?.body?.kind === 'anchor' && !admitted.has(hop.body.to)) {
        return { ok: false, reason: 'anchor-unregistered' };
      }
    }
  }
  for (const hop of sorted) {
    if (!verifyHop(hop)) return { ok: false, reason: 'signature' };
    if (hop.body.kind === 'truncation' && hop.body.from !== hop.body.itemKey) {
      return { ok: false, reason: 'unproven-break' };
    }
    if (!tip) {
      const rooted = hop.body.kind === 'born' && hop.body.priorHead === '';
      if (rooted || hop.body.kind === 'truncation') {
        tip = hop;
        continue;
      }
      return { ok: false, reason: 'prior' };
    }
    if (hop.body.priorHead !== tip.hash) return { ok: false, reason: 'prior' };
    // custody never jumps: the next hop may only be STARTED by a party to
    // the previous hop (born's recipient is the item key — the vendor holds
    // it and its secret by derivation, so a born→flip sale is a party).
    // A verified truncation's holder IS the item key, so the same rule
    // carries custody across the break.
    if (hop.body.from !== tip.body.from
      && hop.body.from !== tip.body.to) {
      return { ok: false, reason: 'custody' };
    }
    if (hop.body.itemKey !== tip.body.itemKey) return { ok: false, reason: 'itemKey' };
    tip = hop;
  }
  if (!tip) return { ok: false, reason: 'empty', tip: null, hasBreak: false };
  return { ok: true, tip, hasBreak: sorted.some((hop) => hop.body.kind === 'truncation') };
}

export function verifyHop(hop) {
  try {
    if (!hop?.body || hop.tag !== HOP_TAG) return false;
    if (bytesToHex(H(HOP_TAG, canonicalBytes(hopBody(hop.body)))) !== hop.hash) return false;
    const required = requiredSignersFor(hop.body);
    for (const role of required) {
      const key = hop.body[role];
      if (!key || !hop.sigs?.[key]) return false;
      if (!verify(hop.sigs[key], canonicalBytes(hopBody(hop.body)), key)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function verifyAnchorHop(hop, anchorKeys) {
  // The single door for reading an anchor hop OUTSIDE a chain: full
  // signature verification, PLUS admission against the reader's own
  // registry key set. Same hard rule as verifyHopChain — a missing,
  // empty, malformed or non-array registry refuses, never a silent pass.
  // Returns { ok:true, reason:'admitted' } or { ok:false, reason }.
  if (!(anchorKeys instanceof Array)) return { ok: false, reason: 'anchor-unregistered' };
  if (!anchorKeys.every((key) => typeof key === 'string' && /^[0-9a-f]{64}$/.test(key.toLowerCase()))) {
    return { ok: false, reason: 'anchor-unregistered' };
  }
  if (!verifyHop(hop)) return { ok: false, reason: 'signature' };
  if (hop.body.kind !== 'anchor') return { ok: false, reason: 'not-anchor' };
  if (!anchorKeys.some((key) => key.toLowerCase() === hop.body.to)) return { ok: false, reason: 'anchor-unregistered' };
  return { ok: true, reason: 'admitted' };
}

export function truncateTitleLineage(itemSecretKey, priorTip, itemKeyPub, at) {
  // a truncation record: new root, parent recorded, prior tip never
  // re-usable. The ITEM KEY signs (attack round three, P2): only the
  // deriver's master secret can produce that key, so the break is
  // self-proving — the verifier needs no master secret at all.
  const body = hopBody({
    kind: 'truncation',
    itemKey: itemKeyPub,
    priorHead: priorTip ? priorTip.hash : '',
    from: itemKeyPub,
    to: itemKeyPub,
    at,
  });
  const sigs = { [body.from]: sign(itemSecretKey, canonicalBytes(body)) };
  return { v: 1, tag: HOP_TAG, hash: hopHash(body), body, sigs };
}
