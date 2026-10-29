# gnark attack vectors: index

<!-- Structure (code-shape slices, D/FP fields, Skip/Drop/Investigate gate) adapted from zkSecurity zk-skills circom-auditor (MIT, (c) 2026 zkSecurity). Vector text is new and gnark-specific. -->

A catalog of soundness, completeness, privacy and integration vectors for gnark
circuits and the code that consumes their proofs. Vectors are grouped by
**code shape**, the construct you grep for, so a vector-scan agent reads one
slice and never the whole catalog.

## Entry format

```text
**V-XX1. Title**

- **D:** the defect, in terms of what the constraints allow
- **FP:** when the same shape is not a bug (the guard that blocks it)
- **Source:** at least one real advisory, audit, PR, or a `gnark/<path>` source
  reference (gnark v0.16.4) that states the API contract
- **Seed:** the gnark-inventory rule (FG-*), an `inventory:` field, a `grep:`
  pattern, or `manual`
- **PoC:** the template id from poc-templates.md
```

Rules for this catalog, checked by `gnark-inventory lint-kb`:

- No vector without a real source. A source is a GHSA advisory, an audit report
  or the PR that fixed an audit finding, a `gnark/<path>` that documents the
  behaviour, or (for generic ZK patterns) the zkSecurity zk-skills catalog entry
  the vector was ported from.
- Ids are unique and never reused. A retired vector keeps its id in a comment.
- `index.md` counts must match the slices.

## Slices

| Slice | Covers | Ids | Count |
|---|---|---|---|
| `attack-vectors/hints.md` | hint outputs, decomposition hints, prover-chosen values | V-H1–V-H7 | 7 |
| `attack-vectors/range-bits.md` | ToBinary, Cmp, rangecheck, bounded comparators, Partition | V-R1–V-R6 | 6 |
| `attack-vectors/field-arith.md` | native wraparound, division, emulated arithmetic | V-F1–V-F8 | 8 |
| `attack-vectors/selector-control.md` | Go control flow, selectors, gated checks, discarded predicates | V-S1–V-S7 | 7 |
| `attack-vectors/hash-merkle.md` | MiMC, Poseidon2, Merkle proofs, variable-length hashing | V-M1–V-M7 | 7 |
| `attack-vectors/curves-signatures.md` | EdDSA, ECDSA, curve membership, exceptional cases | V-E1–V-E7 | 7 |
| `attack-vectors/commitments-recursion.md` | api.Commit, multicommit, in-circuit verifiers, Fiat-Shamir | V-CM1–V-CM8 | 8 |
| `attack-vectors/public-inputs.md` | public-witness order, binding, encoding, unconstrained inputs | V-PI1–V-PI7 | 7 |
| `attack-vectors/verifier-contracts.md` | generated Solidity verifiers and their callers | V-VC1–V-VC6 | 6 |
| `attack-vectors/protocol-state.md` | nullifiers, roots, identity derivation | V-PS1–V-PS4 | 4 |
| `attack-vectors/prover-service.md` | Go code outside Define: setup, keys, deserialization, logs | V-PV1–V-PV6 | 6 |
| `attack-vectors/generic-zk.md` | generic ZK shapes ported from zkSecurity's Circom catalog | V-G1–V-G6 | 6 |
| `attack-vectors/privacy.md` | public inputs, events and calldata, linkable tags, correlation, relayers and indexers, witness exposure | V-PR1–V-PR7 | 7 |
| `attack-vectors/gas-liveness.md` | verifier gas, unbounded loops and payloads, root windows, fillable capacity | V-LV1–V-LV5 | 5 |

Total: 91 vectors.

## Mantras

- **A hint output is a free variable until a constraint pins it.**
- **`reached` is not `bound`.** A hint output in one `AssertIsEqual` can still
  have a second solution. Ask what the constraint forces.
- **Go code in `Define` runs once, at compile time, on placeholders.**
- **Every comparison operand needs a bit bound first.**
- **Every gadget's preconditions are the caller's job unless its doc comment
  says it asserts them.**
- **The public-witness order is the struct walk order, and the contract must
  match it element for element.**
- **Proof bytes are not unique. Never key state on them.**

## Classification gate (vector-scan agents)

For every vector in your slice, output exactly one bucket first:

- **Skip**: the construct and the concept are both absent.
- **Drop**: the construct is present but the FP guard blocks it on every path.
  Quote the guard.
- **Investigate**: no guard, a partial guard, or a guard that may not cover
  every path. Then hunt it.
