// Bitcoin 8 decimals, Monero 12. Round half up, never drop. A float is not a
// coin amount — every amount crossing into the engine is a decimal string,
// every comparison is BigInt units. Ported from Cipher's proofOfTrade.js,
// which already paid for this bug class in the 1-piconero drill.
export const AMOUNT_SCALE = { btc: 8, xmr: 12 };

export function normalizeAmount(value) {
  const raw = typeof value === 'number'
    ? (Number.isFinite(value) ? String(value) : '')
    : String(value ?? '').trim().replace(/[$,]/g, '');
  if (!raw || /e/i.test(raw) || !/^\d+(\.\d+)?$/.test(raw)) {
    throw new Error('The amount must be a decimal string.');
  }
  const [whole, frac = ''] = raw.split('.');
  const digits = whole.replace(/^0+(?=\d)/, '') || '0';
  const trimmed = frac.replace(/0+$/, '');
  return trimmed ? `${digits}.${trimmed}` : digits;
}

export function amountUnits(amount, currency) {
  const scale = AMOUNT_SCALE[String(currency || '').toLowerCase()];
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
  const scale = AMOUNT_SCALE[String(currency || '').toLowerCase()];
  const factor = 10n ** BigInt(scale);
  const whole = units / factor;
  const frac = (units % factor).toString().padStart(scale, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

// The 1-piconero drill: a value crossing a trust edge carries its units with
// it. Nothing in the engine adds or compares amounts that went through
// JavaScript float arithmetic.
export function sumAmounts(pairs) {
  // pairs: [{ amount, currency }] — all entries must share one currency
  let units = 0n;
  let currency = '';
  for (const pair of pairs || []) {
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
