# Answer key — hint-raw fixture

Fixture: `testdata/hint-raw` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize hint-raw <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| H1 | `circuit/circuit.go` Define | `scoreHint(Seed)` output is bound to the public `Score`, but nothing constrains the hint output to equal a deterministic function of `Seed`. | **Critical soundness.** The hint is advisory; a prover overrides it to any value, so `Score` is a free public output while the circuit claims it is derived from `Seed`. PoC: `TestPoC_ScoreUnbound`. | confirmed, critical/high |

A hint output is a free variable until a constraint pins it (V-H1).
