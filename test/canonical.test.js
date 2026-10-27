import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonical, canonicalBytes, encodeParts } from '../src/canonical.js';

// canonical() is injective by construction now — the punch-list close. The
// old renderer aliased null/undefined and NaN/±Infinity, and dropped
// undefined-valued keys, so two DISTINCT bodies could sign the same bytes.
// No constructor ever fed it those values, but the discipline was social;
// this pins the closure in the renderer itself.

test('canonical: every alias class the old renderer had is now distinct', () => {
  const aliased = {
    'undefined-element': canonical([undefined]),
    'null-element': canonical([null]),
    'undefined-key-dropping': canonical({ a: undefined }),
    'null-value': canonical({ a: null }),
    'empty-object': canonical({}),
    nan: canonical(NaN),
    infinity: canonical(Infinity),
    'negative-infinity': canonical(-Infinity),
    'real-null': canonical(null),
    'real-undefined': canonical(undefined),
  };
  const seen = new Map();
  for (const [name, bytes] of Object.entries(aliased)) {
    assert.ok(bytes.length > 0, `${name} renders no empty bytes`);
    assert.ok(!seen.has(bytes), `${name} collides with ${seen.get(bytes) || 'another'}`);
    seen.set(bytes, name);
  }
  // the paired case the old comment named directly
  assert.notEqual(canonical(['a', null]), canonical(['a', undefined]));
  assert.notEqual(canonical({ a: undefined }), canonical({}));
});

test('canonical: honest-domain bytes did not move — the pin', () => {
  // strings, finite integers, booleans, arrays, objects: the JSON path is
  // untouched, so every existing signed body renders the same bytes it
  // always rendered
  assert.equal(
    canonical({ a: 'x', b: 1, c: [true, 'y'], d: { e: 'z' } }),
    '{"a":"x","b":1,"c":[true,"y"],"d":{"e":"z"}}',
  );
  assert.equal(canonical('null'), '"null"', 'a string named null never aliases the null tag');
});

test('canonical: unrenderable values refuse instead of aliasing', () => {
  assert.throws(() => canonical(Symbol('nope')), /refuses this value type/);
  assert.throws(() => canonical({ bad: () => {} }), /refuses this value type/);
  assert.throws(() => canonical(new Promise(() => {})), /refuses this value type/);
});

test('canonical: a laundered pair cannot exchange signatures', () => {
  // the last line of defense: same-key, same-message signatures over two
  // bodies that the old renderer could have collapsed. The bytes differ.
  const honest = canonicalBytes({ v: 1, note: 'a' });
  const laundered = canonicalBytes({ v: 1, note: 'a', extra: null });
  assert.notEqual(honest.length ? [...honest].join(',') : '', [...laundered].join(','));
  assert.notEqual(canonical({ v: 1, x: null }), canonical({ v: 1 }), 'null-keyed value is present');
});

test('canonical: length-prefix join still binds field boundaries', () => {
  // unchanged neighbor sanity: |a|b| never equals |ab| under encodeParts
  assert.notEqual([...encodeParts(['a', 'b'])].join(','), [...encodeParts(['ab'])].join(','));
});
