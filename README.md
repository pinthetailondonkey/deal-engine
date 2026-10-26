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
- `dispute.js` — disputes + resolutions
- `title.js` — per-item custody chain
- `engine.js` — the facade wiring all of it

## Known scope limits (stated, not hidden)

- Salt provenance: one party generates it in the engine; production is
  both parties' randomness mixed. The blinding property (no dictionary
  without a window) holds either way.
- `Genuinely open`, cited from the reports: witness-overlap economics
  under real gossip partitions, partition-vs-fork adjudication as a
  dispute procedure, position-blind (ZK) membership proofs.
