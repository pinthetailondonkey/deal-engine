import { canonicalBytes, bytesToHex, H } from './canonical.js';
import { sign, verify, publicKeyOf } from './keys.js';
import { verifyHop, verifyHopChain } from './title.js';

// Stolen flags on titles: the current keyholder reports a paper stolen.
// Design constraints the earlier attack reports forced onto every
// accusation surface, applied here before one exists:
// - A flag is a defamation primitive unless it can resolve. A stolen flag
//   starts as an open headline a buyer must see ("flagged stolen - do not
//   buy") and resolves through signed facts exactly like money disputes:
//   withdrawn (the filer stood down), cleared or overturned (the filer
//   plus a NAMED arbiter signed it - the police-report leg lives there,
//   outside this code, as the arbiter's own out-of-band procedure).
// - Resolved flags die screaming but never vanish: the history of the
//   flag and its every resolution stays on the paper, including those
//   later overridden. A withdrawal is itself permanent, so a false flag
//   has a provable author to answer for.
// - Keyholder-only: only the holder the chain's tip names may file, and
//   the filer's key is taken from the signature, never from a field.
// - The flag binds to a HOP, not to the paper's tip of the week: when the
//   paper honestly moves on, an unresolved flag stays attached to the
//   history hop it named and travels with the chain a buyer is reading.
//   The verifier determines nothing from who happens to be showing it.
// - Unknown signers are refused (dispute.js round-two). A resolution's
//   arbiter set is the one the verifying door accepted - stored beside
//   the resolution, never self-declared.

export const STOLEN_TAG = 'Deal stolen v1';
export const STOLEN_RESOLUTION_TAG = 'Deal stolen resolution v1';
export const STOLEN_VERDICTS = ['withdrawn', 'cleared', 'overturned'];

export function stolenBody(input = {}) {
  return {
    v: 1,
    kind: 'stolen',
    about: String(input.about || ''), // hash of the hop the flag flew on
    holder: String(input.holder || '').toLowerCase(),
    itemKey: String(input.itemKey || '').toLowerCase(),
    claim: String(input.claim || ''),
    at: requireAt(input.at),
  };
}

function requireAt(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error('The flag needs a time.');
  return value;
}

// The tip hop is the source of every field the filer cannot be trusted
// to supply. The engine takes them, the filer supplies only the words.
export function signStolenFlag(secretKey, tipHop, claim, at) {
  if (!verifyHop(tipHop)) throw new Error('A flag flies on a verified hop.');
  if (!claim) throw new Error('The flag needs a written claim.');
  const body = stolenBody({
    about: tipHop.hash,
    holder: tipHop.body.to,
    itemKey: tipHop.body.itemKey,
    claim,
    at,
  });
  if (publicKeyOf(secretKey) !== body.holder) {
    throw new Error('Only the holder the hop names flags it stolen.');
  }
  return {
    v: 1,
    tag: STOLEN_TAG,
    hash: bytesToHex(H(STOLEN_TAG, canonicalBytes(body))),
    body,
    sig: sign(secretKey, canonicalBytes(body)),
  };
}

export function verifyStolenFlag(flag) {
  try {
    if (!flag?.body || flag.tag !== STOLEN_TAG) return false;
    if (flag.body.kind !== 'stolen') return false;
    if (bytesToHex(H(STOLEN_TAG, canonicalBytes(stolenBody(flag.body)))) !== flag.hash) return false;
    if (!flag.body.about || !flag.body.holder || !flag.body.itemKey || !flag.body.claim) return false;
    return verify(flag.sig, canonicalBytes(stolenBody(flag.body)), flag.body.holder);
  } catch {
    return false;
  }
}

// How the flag sits on a chain being read: 'attached' when its named hop is
// part of the chain and the flag's holder is that hop's recipient; anything
// else names why. The chain argument is the raw hop array; the verifier
// re-walks it entirely, never trusting hop data remembered by the flag.
//
// An unresolved flag on an EARLIER hop stays attached - it was true for
// that hop and no signed fact has stood it down. Whether the buyer reads
// that headline comes from stolenStatus, never from silence.
export function flagOnChain(hops, flag) {
  const checked = verifyHopChain(hops);
  if (!checked?.ok) return { attached: false, reason: 'chain does not check' };
  if (!verifyStolenFlag(flag)) return { attached: false, reason: 'unproven-flag' };
  const liveHops = (Array.isArray(hops) ? hops : []).filter((hop) => verifyHop(hop));
  const named = liveHops.find((hop) => hop.hash === flag.body.about);
  if (!named) return { attached: false, reason: 'old-history-only', tip: checked.tip };
  if (named.body.to !== flag.body.holder) return { attached: false, reason: 'wrong-key' };
  if (named.body.itemKey !== flag.body.itemKey) return { attached: false, reason: 'wrong-key' };
  return { attached: true, at: named.body.at };
}

// The FILER always signs a resolution of their own flag; only withdrawal
// stands on the filer's hand alone. Cleared or overturned also carries a
// NAMED arbiter: sign() only signs here; the admit set is checked at
// verification, taken from the door's storage, NOT from the resolved
// object itself (dispute.js round-three lesson - a resolution can never
// self-declare its arbiters).
export function signStolenResolution(secretKeys, flag, verdict, at) {
  if (!verifyStolenFlag(flag)) throw new Error('A resolution resolves a valid flag.');
  if (!STOLEN_VERDICTS.includes(verdict)) throw new Error('Not a known verdict.');
  const signerList = [].concat(secretKeys);
  if (!signerList.some((secretKey) => publicKeyOf(secretKey) === flag.body.holder)) {
    throw new Error('Only the filer signs a resolution of their flag.');
  }
  if (verdict !== 'withdrawn' && signerList.length < 2) {
    throw new Error('An arbiter must sign a cleared or overturned flag.');
  }
  const body = { v: 1, kind: 'stolen-resolution', resolves: flag.hash, verdict, at: requireAt(at) };
  const sigs = {};
  for (const secretKey of signerList) {
    sigs[publicKeyOf(secretKey)] = sign(secretKey, canonicalBytes(body));
  }
  return {
    v: 1,
    tag: STOLEN_RESOLUTION_TAG,
    resolves: flag.hash,
    body,
    sigs,
  };
}

// The admitted set is arbiter keys the verifying caller accepted, then the
// filer is always admitted. Two arbiters alone still settle nothing, and
// an unknown co-signer poisons the resolution outright.
export function verifyStolenResolution(flag, resolution, arbiterKeys = []) {
  try {
    if (!resolution?.body || resolution.tag !== STOLEN_RESOLUTION_TAG) return false;
    if (resolution.body.kind !== 'stolen-resolution') return false;
    if (!STOLEN_VERDICTS.includes(resolution.body.verdict)) return false;
    if (resolution.body.resolves !== flag?.hash) return false;
    if (!verifyStolenFlag(flag)) return false;
    const message = canonicalBytes(resolution.body);
    const filer = flag.body.holder;
    const admitted = [filer, ...arbiterKeys.map((key) => String(key).toLowerCase())];
    for (const [key, sig] of Object.entries(resolution.sigs || {})) {
      if (!admitted.includes(key)) return false; // no unknown co-signers
      if (!verify(sig, message, key)) return false;
    }
    if (resolution.body.verdict === 'withdrawn') return !!resolution.sigs[filer];
    if (arbiterKeys.length === 0) return false; // an arbiter only names itself at the door
    const arbiterSigned = arbiterKeys.some((key) => !!resolution.sigs?.[String(key).toLowerCase()]);
    return arbiterSigned && !!resolution.sigs[filer];
  } catch {
    return false;
  }
}

// A flag renders as: unresolved ('open', the do-not-buy headline), or
// resolved with its verdict. Resolved flags keep their history; they stop
// screaming. The HEADLINE verdict follows the resolution the parties LAST
// SIGNED (body.at, ties by body digest), not who was appended last - the
// same newest-wins rule money disputes obey.
export function stolenStatus(flag, resolutions = []) {
  const valid = resolutions.map((entry) => {
    const shape = entry?.resolution ? [entry.resolution, entry.arbiterKeys || []] : [entry, []];
    try {
      return verifyStolenResolution(flag, shape[0], shape[1]) ? shape[0] : null;
    } catch {
      return null;
    }
  }).filter(Boolean);
  if (valid.length === 0) return { state: 'open', verdict: '' };
  const newest = [...valid].sort(
    (a, b) => (b.body.at - a.body.at)
      || bytesToHex(H(STOLEN_RESOLUTION_TAG, canonicalBytes(b.body)))
        .localeCompare(bytesToHex(H(STOLEN_RESOLUTION_TAG, canonicalBytes(a.body)))),
  )[0];
  return {
    state: 'resolved',
    verdict: newest.body.verdict,
    history: valid.map((r) => ({ at: r.body.at, verdict: r.body.verdict })).sort((x, y) => x.at - y.at),
  };
}
