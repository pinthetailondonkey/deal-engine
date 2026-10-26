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
| A stranger adjudicates someone else's fork, or the admission is tampered | The admission is itself a signed record over the kept/dropped heads; it must name THIS split and carry the same key that signed the checkpoints; when the view carries a key timeline, the signer must still resolve `valid` at the admission's own time — a since-revoked (stolen) key confirms nothing | `adjudication.test.js` — stranger and tampered sigs fail; revoked-key admission → adjudication-open |
| (Semantics deliberately strengthened) valid pre-revocation evidence alone used to set FORKED | Now pre-revocation evidence without a shared witness stays open — visible but not a verdict; one witness on both sides closes it | `rotation.test.js` — revised on purpose, both shapes pinned |
| Per-item keys were an affine offset of the master — item pubkey predictable from public data, one leaked item secret recovered the master (and with it forged checkpoints) | Derivation hardens to hash-to-curve: the master SECRET goes inside a domain-separated hash with the item id (`H('Deal item key v2', master, itemId, counter) mod n`); one derivation site in `keys.js`, `title.js` delegates | `key-derivation.test.js` — old recovery equations fail, drift is master-dependent, site unified |
| Leaf salt from one party: the vendor could pre-grind a dictionary against its own published leaves | Both parties' randomness mixed at commit: buyer contributes ≥ 8 bytes, the final salt is a domain-separated hash of both, and provenance is returned labeled | `engine.test.js` — degenerate salts throw; window still opens; vendor-only fallback labeled |
| A revealed window leaks more than membership: the co-path names the leaf's position and the tree's size — "correlation is a read" | A second, opt-in surface: an RSA accumulator committed INSIDE the checkpoint signature (`accN`, `accRoot`); `revealDealBlind` returns element + witness and verifies `witness^element === root (mod N)` — no index, no treeSize, no co-path. Refuses membership for records the newest checkpoint never counted, and cross-checks the root against the live log first | `accumulator.test.js` — every index verifies, strangers fail, no positional field in the answer |

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
- `engine.js` — the facade wiring all of it

## Known scope limits (stated, not hidden)

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
