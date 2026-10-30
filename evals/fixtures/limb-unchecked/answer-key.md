# Answer key — limb-unchecked fixture

Fixture: `testdata/limb-unchecked` (gnark v0.14.0, Groth16, BN254). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| H1 | `circuit/circuit.go` Define | The low limb is range-checked to 32 bits, but the high limb from the split hint is never range-checked before recomposition. | **High soundness.** The recomposition `Amount = lo + hi*2^32` holds for a high limb far wider than 32 bits, so `Amount` is effectively unbounded (e.g. a 200-bit value). PoC: `TestPoC_HighLimbUnbounded`. | confirmed, high/medium |

Recomposition holds but a limb is not range-checked (V-H2).
