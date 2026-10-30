# Answer key — nonbool-mux fixture

Fixture: `testdata/nonbool-mux` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize nonbool-mux <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| S1 | `circuit/circuit.go` Define | `Select` is used as a mux weight (`Lane0 + Select*(Lane1-Lane0)`) without `AssertIsBoolean`. | **High soundness.** `api.Select` would assert the selector boolean; the hand-rolled mux does not, so the prover picks any `Select` and makes `Out` an arbitrary affine combination of the lanes, outside `{Lane0, Lane1}`. PoC: `TestPoC_NonBooleanSelector`. | confirmed, high/medium |

Selector not constrained to its domain (V-S2).
