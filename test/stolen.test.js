import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { itemKeyPair, signHop, hopBody } from '../src/title.js';
import {
  stolenBody,
  signStolenFlag,
  verifyStolenFlag,
  flagOnChain,
  signStolenResolution,
  verifyStolenResolution,
  stolenStatus,
} from '../src/stolen.js';

const maria = generateKey(); // the vendor who mints
const jo = generateKey();    // the first holder
const thief = generateKey(); // a stranger to the chain
const arbiter = generateKey(); // the named third hand (the police-report leg)

const T0 = 1_740_000_000_000;

function buildChain(itemId = 'bike-7') {
  const item = itemKeyPair(maria.secretKey, itemId);
  const born = signHop([maria.secretKey, jo.secretKey], hopBody({
    kind: 'born', itemKey: item.publicKey, priorHead: '',
    from: maria.publicKey, to: jo.publicKey, at: T0,
  }));
  return { item, chain: [born], born };
}

test('stolen: the keyholder files a signed flag that binds to their hop', () => {
  const { chain, born } = buildChain();
  const flag = signStolenFlag(jo.secretKey, born, 'The bike left with the car.', T0 + 10);
  assert.equal(verifyStolenFlag(flag), true);
  assert.equal(flag.body.holder, jo.publicKey, 'the filer is the hop the chain names');
  assert.equal(flag.body.about, born.hash, 'the flag names the hop, not the tip of the week');
  const gate = flagOnChain(chain, flag);
  assert.equal(gate.attached, true, 'the flag flies on an honest chain');
});

test('stolen: only the holder the hop names may file', () => {
  const { born } = buildChain();
  assert.throws(() => signStolenFlag(thief.secretKey, born, 'Not my bike.', T0 + 11),
    /holder the hop names/);
  // and a flag whose holder is a stranger's key will never shape up, even
  // hand-forged: the signature must come from body.holder itself
  assert.equal(verifyStolenFlag({
    v: 1, tag: 'Deal stolen v1',
    hash: '00'.repeat(32), body: stolenBody({
      about: born.hash, holder: thief.publicKey, itemKey: 'x', claim: 'lie', at: T0 + 12,
    }), sig: 'aa',
  }), false, 'a stranger-flagged paper refuses at the door');
});

test('stolen: the flag rides the chain it named, later hops included', () => {
  const { item, chain, born } = buildChain();
  const dana = generateKey();
  const flag = signStolenFlag(jo.secretKey, born, 'Sold under duress.', T0 + 20);
  // the paper moves honestly AFTER the flag: the flag stays attached to the
  // history hop it named, and the buyer reading the longer chain still must see it
  const flip = signHop([jo.secretKey, dana.secretKey], hopBody({
    kind: 'flip', itemKey: item.publicKey, priorHead: born.hash,
    from: jo.publicKey, to: dana.publicKey, at: T0 + 30,
  }));
  const longer = [...chain, flip];
  assert.equal(flagOnChain(longer, flag).attached, true, 'an open flag persists through custody');
  // but a flag naming a hop NOT in this chain detaches from this paper
  const other = buildChain('bike-8');
  assert.equal(flagOnChain(longer, signStolenFlag(jo.secretKey, other.born, 'other paper', T0 + 40)).attached,
    false, 'a flag for another bike does not ride this chain');
  // wrong-key binding: a flag re-pointed at a hop it did not fly on
  const retargeted = { ...flag, body: { ...flag.body, holder: dana.publicKey } };
  retargeted.hash = '11'.repeat(32); // hash no longer matches the body: the door refuses
  assert.equal(flagOnChain(longer, retargeted).attached, false, 'a re-pointed flag refuses');
});

test('stolen: the filer can withdraw - with provable authorship', () => {
  const { chain, born } = buildChain();
  const flag = signStolenFlag(jo.secretKey, born, 'Found it in the shed.', T0 + 50);
  assert.throws(() => signStolenResolution([thief.secretKey], flag, 'withdrawn', T0 + 60),
    /Only the filer signs/);
  const resolution = signStolenResolution([jo.secretKey], flag, 'withdrawn', T0 + 60);
  assert.equal(verifyStolenResolution(flag, resolution), true);
  assert.equal(stolenStatus(flag, [resolution]).state, 'resolved', 'a withdrawal stops the screaming');
  assert.equal(stolenStatus(flag, []).state, 'open', 'unresolved, it stays the headline');
  // history keeps the withdrawal anything claims it never happened
  assert.deepEqual(stolenStatus(flag, [resolution]).history, [{ at: T0 + 60, verdict: 'withdrawn' }]);
});

test('stolen: cleared or overturned needs an arbiter the door names', () => {
  const { chain, born } = buildChain();
  const flag = signStolenFlag(jo.secretKey, born, 'Report filed with police.', T0 + 70);
  // filer alone cannot clear their own flag
  assert.throws(() => signStolenResolution([jo.secretKey], flag, 'cleared', T0 + 80),
    /arbiter must sign/);
  const duo = signStolenResolution([jo.secretKey, arbiter.secretKey], flag, 'cleared', T0 + 80);
  assert.equal(verifyStolenResolution(flag, duo), false, 'no arbiter named, no clear');
  assert.equal(verifyStolenResolution(flag, duo, [arbiter.publicKey]), true,
    'the verifying door proves the arbiter it accepted');
  // two arbiters alone settle nothing, and an unknown co-signer poisons it
  const stranger2 = generateKey();
  const poisoned = { ...duo, sigs: { ...duo.sigs, [stranger2.publicKey]: stranger2.publicKey } };
  assert.equal(verifyStolenResolution(flag, poisoned, [arbiter.publicKey]), false,
    'an unknown co-signer poisons the resolution');
  // a resolved clear keeps the filer's hand: nobody else resolves for them
  assert.equal(stolenStatus(flag, [{ resolution: duo, arbiterKeys: [arbiter.publicKey] }]).verdict, 'cleared');
});

test('stolen: newest signed verdict wins, ties by digest', () => {
  const { chain, born } = buildChain();
  const flag = signStolenFlag(jo.secretKey, born, 'Two stories exist.', T0 + 100);
  const withdrawn = signStolenResolution([jo.secretKey], flag, 'withdrawn', T0 + 200);
  const duo = signStolenResolution([jo.secretKey, arbiter.secretKey], flag, 'overturned', T0 + 300);
  // the ordering follows body.at, not the array order
  const status = stolenStatus(flag, [
    { resolution: duo, arbiterKeys: [arbiter.publicKey] },
    withdrawn,
  ]);
  assert.equal(status.verdict, 'overturned', 'the later signature carries the headline');
  assert.equal(status.history.length, 2, 'every resolution stays in the history');
});

test('stolen: garbage refuses everywhere, never crashes the honest reader', () => {
  assert.equal(verifyStolenFlag(null), false);
  assert.equal(verifyStolenFlag({ body: stolenBody({ at: 1 }) }), false);
  assert.equal(flagOnChain([], null).attached, false);
  assert.equal(stolenStatus(null, [null, {}]).state, 'open', 'shapeless resolutions do not clear a flag');
});
