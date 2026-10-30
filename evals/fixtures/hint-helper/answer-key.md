# Answer key — hint-helper fixture

Fixture: `testdata/hint-helper` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize hint-helper <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| H1 | `circuit/circuit.go` `toByte` | `toByte` returns the `bitsHint` outputs without asserting each is boolean or that they recompose to the input; `Meter.Define` consumes `b[7]` as a parity bit. | **High soundness.** Every caller assumes the helper constrained its outputs. It did not, so `b[7]` (and all bits) are free: the published `Parity` can be forged and `Reading` is never range-checked. PoC: `TestPoC_HelperUnconstrained`. | confirmed, high/medium |

Helper returns hint outputs and the caller assumes it constrained them (V-H7).
