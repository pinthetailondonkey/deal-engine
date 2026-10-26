import { test } from 'node:test';
import assert from 'node:assert/strict';
import { amountUnits, unitsToAmount, normalizeAmount, sumAmounts } from '../src/units.js';

test('money: a float is not a coin amount — numbers only enter as finite strings', () => {
  assert.equal(amountUnits('0.000000000001', 'xmr'), 1n); // 1 piconero
  // hardened after attack round two: a number is refused outright —
  // String(0.1+0.2) used to become a SIGNED amount of 0.30000000000000004
  assert.throws(() => normalizeAmount(0.5), /not a coin amount/);
  assert.equal(amountUnits(0.5, 'xmr'), null, 'number input refuses to a null unit count');
  assert.throws(() => normalizeAmount(Number.NaN));
  assert.throws(() => normalizeAmount(Number.POSITIVE_INFINITY));
  assert.throws(() => normalizeAmount('1e-12'), /decimal string/);
  assert.equal(amountUnits('0.5', 'xmr'), 500000000000n);
});

test('money: the 1-piconero drill — nothing tiny ever confirms as big', () => {
  // watcher→app drill: 1 piconero must NEVER equal half an XMR on crossing
  const tiny = amountUnits('0.000000000001', 'xmr');
  const half = amountUnits('0.5', 'xmr');
  assert.ok(tiny < half);
  assert.notEqual(tiny, half);
  assert.equal(unitsToAmount(tiny, 'xmr'), '0.000000000001');
  assert.equal(unitsToAmount(half, 'xmr'), '0.5');
});

test('money: round half up, never drop', () => {
  assert.equal(amountUnits('0.0000000000051', 'xmr'), 5n);
  assert.equal(amountUnits('0.0000000000055', 'xmr'), 6n); // rounds up at .5
  assert.equal(amountUnits('0.004999999', 'btc'), 500000n); // 9th digit 9 >= 5 → half-up, not floored
});

test('money: two currencies never sum', () => {
  assert.throws(() => sumAmounts([
    { amount: '0.5', currency: 'xmr' },
    { amount: '0.5', currency: 'btc' },
  ]), /two currencies/);
});

test('money: sum keeps precision at scale', () => {
  const out = sumAmounts([
    { amount: '0.1', currency: 'xmr' },
    { amount: '0.1', currency: 'xmr' },
    { amount: '0.1', currency: 'xmr' },
    { amount: '0.1', currency: 'xmr' },
    { amount: '0.1', currency: 'xmr' },
  ]);
  assert.equal(out.amount, '0.5');
  assert.equal(out.units, 500000000000n);
});
