# Answer key — hint-remainder fixture

Fixture: `testdata/hint-remainder` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize hint-remainder <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| H1 | `circuit/circuit.go` Define | `Count = q*Size + r` is the only check on the Euclidean hint; `r` is never bound to `[0, Size)`. | **High soundness.** Over the field every `q` has a matching `r = Count - q*Size`, so the published `Quotient` is unconstrained: `17/5` can be proven as `4`. PoC: `TestPoC_QuotientFree`. | confirmed, high/medium |

Quotient/remainder hint without `remainder < divisor` (V-H3).
