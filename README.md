# Deal engine

The protocol layer of the Deal design, rebuilt from the adversarial-review
reports. Pure functions, no relay, no wallet, no UI. Every module below
exists because a report demanded it; every defense is pinned by a test.

Run: `npm test` (node --test). Dependencies: `@noble/curves@^2.4.0`,
`@noble/hashes@^2.4.0` — BIP340 Schnorr + SHA-256 only, same family the
Cipher app already uses.

## Attack report → engine defense → proof

| Report finding | Defense | Proof |
| --- | --- | --- |
| Count forgery: 160 burner keys pass every check; nothing can see inside a body | The count is reported only as "witnessed deals in the latest checkpoint", with size history deltas; evidence windows are the honesty mechanism | `engine.test.js` — count is tree size in a signed STC, deltas sorted |
| Witnesses never signed content — same checkpoint could differ per witness | Witness statements are fixed-serialization signatures over `{stcHead, witnessTime, prevStcHead}`; the statement bytes bind the checkpoint's canonical bytes | `checkpoint.test.js` — statement fails against any other STC bytes |
| Witness self-declaration ("no contradictions" was vacuous) | Checkpoints carry a signed witness registry; a statement counts only if its key is admitted | `checkpoint.test.js` — outsider can't sign, registry swap fails |
| Fork with disjoint witness sets, zero collusion | Fork evidence = two valid STCs on the same `prevHead` with different root/size; verifiable by anyone holding both | `checkpoint.test.js`, `standing.test.js` — evidence verifies; states are not mutually exclusive |
| Cadence ratchet 7d → 365d | Cadence is a protocol constant, absent from the checkpoint object | `checkpoint.test.js` — no cadence field exists at all |
| "extends prior ✓" was a social claim | Every STC field — seq, size, root, prevHead — is inside the signature; continuity is a computed check (RFC 6962 consistency proofs) | `merkle.test.js` — brute-force (m,n) grids; `standing.test.js` — broken chain shows |
| Months of unwitnessed prefix = free rewrite + TRUNCATED escape hatch | Only witnessed checkpoints confirm history; TRUNCATED is a recorded lineage break with an unreachable parent, never an edit | `title.test.js` — break is visible forever |
| Leaf = hash(deal) leaks via co-path + dictionary attack | Leaves are blinded: `H(salt ‖ record)`; salt co-set at commit, revealed only in a granted window | `engine.test.js` — no salt, no membership oracle |
| leaf-as-node replay | RFC 6962 leaf 0x00 / interior 0x01 prefixes, domain separation on every hash | `merkle.test.js` — CT skeleton shape test |
| Witness club / unrotating witness sets | Registry format supports rotation; the engine refuses statements from keys not admitted per-checkpoint | `checkpoint.test.js` |
| Refunds still counted forever, count never decrements | Void statement sits BESIDE the count on a visible signed ledger | `engine.test.js` — count stays 1, void visible |
| Dispute = permanent extortion badge | Resolutions are first-class co-signed records (`settled`/`withdrawn`/`overturned`); withdrawal needs the filer's own sig; strangers cannot sign | `dispute.test.js` — forged resolution never overwrites |
| Chains not per-item keyed → cross-item linkability | Per-item derived keys from (master, itemId); two titles share no key | `title.test.js` |
| Orphan flips forge a chain with bogus prior | First hop must be rooted or a recorded truncation break | `title.test.js` — orphan → `{ok:false, reason:'prior'}` |
| Stolen vendor key extends the line seamlessly | Dual-signed rotation (old+new); revocation retires a key self-signed; the key timeline grades every checkpoint at its own issue time | `rotation.test.js`, `engine.test.js` — post-revocation checkpoints never count; pre-revocation standing is untouched |
| A stolen witness key mints fork libel against an honest vendor ("permanent, independently verifiable" scar) | Fork evidence is graded against the key timeline: fully post-revocation evidence is suspect-without-verdict, never FORKED | `rotation.test.js` — libel gate; pre-revocation evidence still bites |
| Witness rotation as a self-claim | A rotated witness key inherits admission only through a dual-signed rotation reaching back to a registry-admitted key | `rotation.test.js`, `checkpoint.js` `admittedWitness` |
| FORKED from equal-strength evidence alone: the accused vendor has no answer to a partition (the reports' hardest question) | FORKED now requires adjudication: **fork-proved** = one admitted witness signed BOTH sides of the split (every statement signature re-checked, never trusted) or **vendor-confirmed** = a signed admission naming the kept line, signed by the checkpoints' own key; everything stays **adjudication-open** otherwise — visible, un-accused | `adjudication.test.js`, `standing.test.js` |
| The vendor's verdict named a kept line but the DEAD line kept driving freshness, count and continuity (attack round two) | A vendor-confirmed verdict prunes its dropped head and every descendant from checkpoint selection; freshness is computed from the kept line, and `details.adjudicatedKept` surfaces which line the admission named | `standing.test.js` — dead, extended, witnessed line no longer reads CURRENT |
| A forged statement buys a shared witness — and so did a STRANGER'S own key: signature-only filtering let anyone close any fork (attack round two) | adjudicateFork routes every statement through the full witness machinery (tag, stcHead binding, witnessTime, registry-or-rotation admission) against the side it names; a key admitted nowhere cannot speak, however well-formed its statement | `adjudication.test.js` — stranger with valid sigs stays open; rotated witness still counts through the rotation chain |
| An empty-root checkpoint "committed" to nothing and an identity accRoot admitted any witness; empty roots also posed as a consistency pair | Body-level shape validation at the only door a body enters: root must be 64-hex, prior head 64-hex or empty at genesis, accumulator fields hex bytes of digest width; `verifyBlindMembership` refuses degenerate roots and elements ≤ 1; `verifyConsistencyProof` requires real roots even for m = n; Miller–Rabin bases now derive from the candidate | `shape.test.js` — the t7 empty-root STC verifies as nothing; the e = 0 forgery refused |
| The accumulator trapdoor was a public return value: `(p, q)` came out of `generateModulus` and `engine.accKey()` — anyone holding the engine object held the factorization | `(p, q)` stay inside the accumulator module's cache; both surfaces return `{ n, bits }` only. Stated harder: seed reuse is not "risky", it is wholesale breakage — a shared seed IS a shared factorization | `shape.test.js` — both answers carry exactly two keys, neither named p or q |
| The view seams took whatever the caller handed them: a doctored timeline resurrected a revoked key (duplicate entry wins), a foreign key listed as role 'witness' licensed checkpoints, a future-dated checkpoint read CURRENT for ~97 years, a stranger-signed refusal flipped the view, refusals aged out leaving no trace, and `'🔫'.length` counted as two voided deals | Duplicate timeline entries resolve to NOTHING (not last-wins); checkpoint and fork grading require role `vendor`; witness keys on the timeline must resolve valid at the checkpoint's issue time (unknown ≠ revoked — the registry keeps its authority); a future-dated checkpoint or refusal confers nothing and is flagged in `details`; `details.refusalHistory` keeps every valid refusal after it stops screaming; view fields degrade to empty arrays instead of crashing; void entries count only when structurally signed void statements | `standing.test.js`, `rotation.test.js` |
| The title verifier authenticated nothing: a flip rooted on an empty priorHead, custody jumped to alien keys, a different item's key was spliced mid-chain, null relay data crashed the honest verifier, and an empty chain read VERIFIED | Only a born hop with no parent (or a recorded truncation) roots a lineage; custody never jumps — the next hop starts at a party to the previous hop; the itemKey is pinned constant along the chain; null entries degrade to not-verified; an empty chain is explicitly not verified | `title.test.js`, `s7` repro — all four forgeries now refuse |
| The facade trusted callers one layer too deep: one dealId committed twice (double count, unaddressable second record), re-filing a dispute wiped its resolutions, committed records and returned checkpoints were live mutable references, seq went backward, a bad/differing accSeed was silently ignored, buyerSalt accepted `0x` and non-hex junk, the blind reveal trusted ungated checkpoints, reveals said nothing about voidedness, two arbiters could settle over absent parties, and the dispute headline followed array order | dealId uniqueness in the log; re-file of a known dispute is a no-op; deep copies at the store AND return boundaries (commit, checkpoint, witness, refusal); seq must strictly increase; the accSeed is validated at the door and pinned for the engine's life; salt bytes are strict lowercase hex; the blind reveal passes the same key-timeline gate as publicState; reveals carry `voidedBy` when one exists; both parties sign every verdict (arbiters only when the caller names them); the headline verdict follows `body.at`, with the full history surfaced | `key-derivation.test.js`, `standing.test.js`, `shape.test.js`, `dispute.test.js`, `units.test.js` — plus the a*/s*/t* repro scripts, which now all refuse at the front door |
| Money inputs mutated silently: floats signed as amounts, `'1,5'` normalized to `'15'`, negative units rendered `0.0000000000-5`, an empty sum threw an opaque TypeError | A number is refused outright ("a float is not a coin amount"); commas are only 3-digit grouping, else refused; negative units render `-1.5`; `sumAmounts([])` is an explicit zero; unknown currencies and float units are domain errors, not TypeErrors | `units.test.js` — half-up boundaries re-pinned exact |
| A stranger adjudicates someone else's fork, or the admission is tampered | The admission is itself a signed record over the kept/dropped heads; it must name THIS split and carry the same key that signed the checkpoints; when the view carries a key timeline, the signer must still resolve `valid` at the admission's own time — a since-revoked (stolen) key confirms nothing | `adjudication.test.js` — stranger and tampered sigs fail; revoked-key admission → adjudication-open |
| (Semantics deliberately strengthened) valid pre-revocation evidence alone used to set FORKED | Now pre-revocation evidence without a shared witness stays open — visible but not a verdict; one witness on both sides closes it | `rotation.test.js` — revised on purpose, both shapes pinned |
| Per-item keys were an affine offset of the master — item pubkey predictable from public data, one leaked item secret recovered the master (and with it forged checkpoints) | Derivation hardens to hash-to-curve: the master SECRET goes inside a domain-separated hash with the item id (`H('Deal item key v2', master, itemId, counter) mod n`); one derivation site in `keys.js`, `title.js` delegates | `key-derivation.test.js` — old recovery equations fail, drift is master-dependent, site unified |
| Leaf salt from one party: the vendor could pre-grind a dictionary against its own published leaves | Both parties' randomness mixed at commit: buyer contributes ≥ 8 bytes, the final salt is a domain-separated hash of both, and provenance is returned labeled | `engine.test.js` — degenerate salts throw; window still opens; vendor-only fallback labeled |
| A revealed window leaks more than membership: the co-path names the leaf's position and the tree's size — "correlation is a read" | A second, opt-in surface: an RSA accumulator committed INSIDE the checkpoint signature (`accN`, `accRoot`); `revealDealBlind` returns element + witness and verifies `witness^element === root (mod N)` — no index, no treeSize, no co-path. Refuses membership for records the newest checkpoint never counted, and cross-checks the root against the live log first | `accumulator.test.js` — every index verifies, strangers fail, no positional field in the answer |
| Facade round three: raw `dealId`s collided inside the uniqueness gate after canonical() folded two bodies into one string; mutating a returned resolution rewound a settled dispute to open; a re-filed dispute wiped its history; an arbitered settlement graded open on the status surface; a door-seeded engine published no `accN` (and a differing seed silently re-seeded) | Bodies are stored and keyed on the bytes signatures actually bind (`recordBody`); every stored and returned dispute/resolution/void/evidence object is a deep copy; re-filing a known dispute is a no-op; the arbiter set the door accepted rides WITH the stored resolution into `disputeStatus`; the seed check runs before the lazy modulus gate, and a door-seeded engine publishes `accN` from its own stored seed every checkpoint | `engine.test.js` — raw-dealId collision pin, laundering mutation pins, arbitered settlement pin, accSeed identity pin |
| Protocol round three: a revoked witness key seated a successor forever through a backdated 'unknown' rotation; any observer grafted a self-signed truncation onto an honest chain and inherited custody; garbage truthy values flipped the `truncated`/`breached` headline flags; `adjudicateFork` believed a degenerate evidence pair and closed a fork with ONE honest statement | A key the timeline retired before a checkpoint passes its seat to nobody (`admittedWitness` rides a live source seat); a truncation must be signed by the ITEM KEY ITSELF — self-proving, no verifier needs the master — and custody applies with no exemptions; `truncated` takes a verifiable truncation hop and `breached` a real boolean, garbage flagged in details; `adjudicateFork` runs `verifyForkEvidence` on its own input — unevidenced input grades open with reason 'unevidenced' | `standing.test.js`, `title.test.js`, `adjudication.test.js` — laundered rotation seats nobody; foreign truncation refuses; degenerate pair proves nothing |
| Crypto round three, the forged header: `verifyBlindMembership` took `(root, n)` as loose strings, and `n' = R·(R−1)` made `R^e ≡ R` — witness = R admitted any element against the vendor's own root | Structural gates at the string level (odd modulus, modulus > root, modulus not divisible by the root, witness ≠ root) kill the paper family, stated as HEURISTICS; the closing rule is signature-bound pairing — `verifyBlindMembershipIn` re-verifies the checkpoint, applies the key-timeline gate, and reads BOTH fields from that one signed body; the engine's blind self-check goes through it | `accumulator.test.js` — forged headers refused, bound surface honest-verify, tampered body and stranger timeline refuse; `attack6` repro now refuses |
| A stolen flag without a resolution path is a permanent defamation primitive, and a forgery could fly on any hop | Stolen flags are first-class signed statements filed by the holder the chain's tip names, bound to ONE hop hash (they stay attached to that history hop as the paper moves on); every flag resolves — `withdrawn` (filer's hand alone, permanently provable authorship), `cleared`/`overturned` (filer + a NAMED arbiter the verifying door admits, the police-report leg living outside this code); unknown co-signers poison; the newest signed verdict carries the headline while the full history stays | `stolen.test.js` — stranger cannot file or sign, flags ride later flips, hand-forged bodies refuse at the door, pulled arbiters leave nothing but open |

And two things the engine deliberately does NOT do (the reports' honest
split): it does not anchor a phone to the physical world — that is an
external attestation record (`anchor` hop), never engine-computed truth;
and a committed count says nothing about a stranger's seriousness — the
count is a self-declared, witnessed tree size, worded exactly that way.

## Module map

- `canonical.js` — length-prefixed canonical bytes + domain-separated `H`
- `keys.js` — Schnorr keys, per-item derivation
- `units.js` — BTC 8 / XMR 12, BigInt units, round half up, string-only amounts
- `record.js` — dual-signed deal records + void statements
- `merkle.js` — RFC 6962 tree, inclusion + consistency proofs
- `checkpoint.js` — signed tree checkpoints, witness statements, fork evidence, refusals
- `log.js` — blinded log + commits
- `standing.js` — the 7-state lifecycle on the observer's clock
- `adjudication.js` — the fork procedure: fork-proved / vendor-confirmed / adjudication-open
- `accumulator.js` — position-blind membership (RSA accumulator, pure BigInt)
- `dispute.js` — disputes + resolutions
- `title.js` — per-item custody chain
- `stolen.js` — stolen flags on titles + their resolutions
- `engine.js` — the facade wiring all of it

## Known scope limits (stated, not hidden)

These are written into the module docs themselves — the code that carries
each limit is where the honest sentence lives:

- **Backdating window** (`rotation.js`): timestamps are self-claimed. A
  thief with a stolen live key can forge bodies dated before the
  revocation; the forgery window is bounded only by the revocation tick
  itself. Closing it needs timestamps from outside the key holder.
- **Rotation-tick false alarm** (`rotation.js`): a body dated at the exact
  millisecond of a rotation or revocation is refused, on purpose — an
  honest signer hitting the exact tick also gets refused, visibly, and
  re-issues clean one millisecond later.
- **RFC 6962 consistency-proof shape** (`merkle.js`): hashing matches the
  RFC; the consistency-proof shape is this module's own. Self-consistent,
  pinned by tests, but NOT interoperable with a Certificate-Transparency
  implementation. If PoT v2 needs real CT interop, this module changes.
- **canonical() non-injectivity** (`canonical.js`): distinct values can
  render the same bytes (`null`/`undefined`, `NaN`/`Infinity`). Every
  signed body is built by a validating *Body() constructor first — any new
  signed surface must keep that discipline.
- **Loose-string blind verification** (`accumulator.js`): the string-level
  `verifyBlindMembership` gates are heuristics, not proof — a patient
  forger can shape an odd composite (e.g. `n' = w^e − root`) that slips
  them. The closing rule is one layer up: read `(root, n)` from ONE
  verified signed checkpoint body and check with
  `verifyBlindMembershipIn` (`checkpoint.js`).
- **Anchor attestation** (`title.js`): the verification hole is
  closed — an anchor hop verifies only when the READER holds an admitted
  registry key set (`opts.anchorKeys`) and the anchor's signing key is in
  it; anchor-bearing chains arriving with no registry refuse outright
  (`anchor-unregistered`). What no code can promise: that the registry
  actually performed its out-of-band check of the physical item. The
  attestation's real strength stays the registry's own procedure, outside
  this code.

- Salt provenance: closed. The vendor always brings fresh bytes; the buyer
  MAY contribute at least 8 bytes and the stored salt is
  `H('Deal salt mix v1', vendorSalt, buyerSalt)` — never a concatenation
  a dictionary attack could peel apart. Provenance is returned and
  labeled ('vendor' vs 'vendor+buyer'); the blinding property holds even
  when only the vendor contributes. What remains a market question:
  making sure buyers actually contribute.
- `Genuinely open`, cited from the reports: witness-overlap economics
  under real gossip partitions (a market question). Partition-vs-fork
  is now an adjudication procedure, not an open question; position-blind
  (ZK) membership is now the opt-in accumulator surface. What remains
  open is when honest witnesses END UP shared — the engine cannot make
  them — and batch membership proofs (witness updates on append are
  linear; a production log would amortize with batch trees).
