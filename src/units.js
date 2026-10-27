// Bitcoin 8 decimals, Monero 12. Round half up, never drop. A float is not a
// coin amount — every amount crossing into the engine is a decimal string,
// every comparison is BigInt units. Ported from Cipher's proofOfTrade.js,
// which already paid for this bug class in the 1-piconero drill.
//
// Attack round two (finding 7 / API F12), now enforced, not just written:
// numbers are refused outright (String(0.1+0.2) used to slip through as a
// signed amount), a comma INSIDE digits is a domain error (comma stripping
// used to rewrite '1,5' into '15'), a negative unit count renders sanely,
// and the empty sum is an explicit result, not a TypeError.
//
// Founder ruling ("deal should work with all crypto not just btc and xmr"):
// the pair stops being written out by hand. ASSETS is the one row-per-rail
// table — decimals is the atomic-unit power (the piconero class bug is the
// thing every future row must get right); chain records whether the chain
// itself shows amounts ('transparent') or hides them ('hidden-amount'),
// which is what a bulletin/stats law reads, not what the engine compares.
// Adding a coin is a row plus a watcher, never engine surgery: everything
// below reads the table through scaleOf, and AMOUNT_SCALE stays exported by
// its old name because a scale is the only fact this layer ever had to
// expose. Confirmation depth, address formats and watcher hooks live
// app-side and in the watcher, not here — the engine consents to a
// settlement record, it never talks to a chain.
export const ASSETS = {
  btc: { decimals: 8, chain: 'transparent' },
  xmr: { decimals: 12, chain: 'hidden-amount' },
};

// The scale map, by its old name — one decimal power per rail.
export const AMOUNT_SCALE = Object.fromEntries(
  Object.entries(ASSETS).map(([rail, asset]) => [rail, asset.decimals]),
);

function scaleOf(currency) {
  return AMOUNT_SCALE[String(currency || '').toLowerCase()];
}

export function normalizeAmount(value) {
  if (typeof value === 'number') {
    throw new Error('A float is not a coin amount: pass a decimal string.');
  }
  const raw = String(value ?? '').trim();
  if (!raw || /e/i.test(raw) || !/^\d+([,.]\d+)?$/.test(raw) || /,/.test(raw) && !/^(\d{1,3})(,\d{3})*(\.\d+)?$/.test(raw)) {
    throw new Error('The amount must be a decimal string — group digits with commas in threes, or use plain digits.');
  }
  const digits = raw.replace(/,/g, '');
  const [whole, frac = ''] = digits.split('.');
  const wholeDigits = whole.replace(/^0+(?=\d)/, '') || '0';
  const trimmed = frac.replace(/0+$/, '');
  return trimmed ? `${wholeDigits}.${trimmed}` : wholeDigits;
}

export function amountUnits(amount, currency) {
  const scale = scaleOf(currency);
  if (scale == null) return null;
  let text;
  try {
    text = normalizeAmount(amount);
  } catch {
    return null;
  }
  const [whole, frac = ''] = text.split('.');
  const factor = 10n ** BigInt(scale);
  if (frac.length <= scale) {
    return BigInt(whole) * factor + BigInt((frac || '0').padEnd(scale, '0'));
  }
  // round half up, never drop: one extra digit decides, nothing else counts
  let units = BigInt(whole) * factor + BigInt(frac.slice(0, scale) || '0');
  if (Number(frac[scale]) >= 5) units += 1n;
  return units;
}

export function unitsToAmount(units, currency) {
  if (!Number.isInteger(units) && typeof units !== 'bigint') {
    throw new Error('Units are an integer (BigInt). A float is not a coin amount.');
  }
  const value = BigInt(units);
  const scale = scaleOf(currency);
  if (scale == null) throw new Error(`Unknown currency: ${String(currency)}`);
  const factor = 10n ** BigInt(scale);
  const sign = value < 0n ? '-' : '';
  const abs = value < 0n ? -value : value;
  const whole = abs / factor;
  const frac = abs % factor;
  const fracText = frac.toString().padStart(scale, '0').replace(/0+$/, '');
  return `${sign}${fracText ? `${whole}.${fracText}` : `${whole}`}`;
}

// The 1-piconero drill: a value crossing a trust edge carries its units with
// it. Nothing in the engine adds or compares amounts that went through
// JavaScript float arithmetic.
export function sumAmounts(pairs) {
  if (!Array.isArray(pairs)) throw new Error('The sum takes a list of amounts.');
  if (pairs.length === 0) return { currency: '', units: 0n, amount: '0' };
  // pairs: [{ amount, currency }] — all entries must share one currency
  let units = 0n;
  let currency = '';
  for (const pair of pairs) {
    const one = amountUnits(pair.amount, pair.currency);
    if (one == null) throw new Error('A refused amount reached the sum.');
    if (!currency) currency = String(pair.currency).toLowerCase();
    else if (currency !== String(pair.currency).toLowerCase()) {
      throw new Error('Amounts of two currencies were summed.');
    }
    units += one;
  }
  return { currency, units, amount: unitsToAmount(units, currency) };
}
