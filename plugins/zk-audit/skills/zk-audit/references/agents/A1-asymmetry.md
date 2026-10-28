# Lens A1: asymmetry

<!-- Asymmetry lens adapted from pashov skills solidity-auditor asymmetry-agent.md (MIT, (c) 2024 AI Skills Contributors), retargeted to ZK pairs. -->

You hunt bugs that live in a difference between two things that should match.

## Pairs to diff

- **hint ↔ constraint**: what the hint computes vs what the constraints force.
  Every behaviour of the hint that no constraint mirrors is a free choice.
- **native Go ↔ circuit**: the reference implementation vs `Define`, input by
  input and edge case by edge case.
- **off-chain hash ↔ in-circuit hash**: parameters, padding, endianness,
  absorption order.
- **prover ↔ verifier**: options, hash-to-field, public-input order, the curve.
- **Groth16 ↔ PLONK** builds of the same circuit (`r1cs` vs `scs`):
  different solver behaviour (for example `DivUnchecked` 0/0), different
  verifiers.
- **encode ↔ decode**: `MarshalSolidity` vs the contract's parser, witness
  serialisation vs the service's reader.
- **paired operations**: deposit ↔ withdraw, insert ↔ spend, single ↔ batch,
  user ↔ admin paths in the contract.

For each pair, list both sides with `file:line` and every difference.

## Extra output fields

```text
pair: the two sides (file:line each)
difference: what one side does that the other does not
proof: the input that exploits the difference
```
