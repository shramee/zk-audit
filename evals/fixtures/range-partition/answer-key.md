# Answer key — range-partition fixture

Fixture: `testdata/range-partition` (gnark v0.14.0, Groth16, BN254). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| R1 | `circuit/circuit.go` Define | `Lo` is range-checked to 20 bits while the split point is `2^16`, so `Lo`'s range overlaps the high part `Hi`. | **High soundness.** A given `Packed` has several `(Lo, Hi)` splits, so the exposed high part `Hi` is prover-chosen (e.g. `65536` splits as `Hi=1,Lo=0` or `Hi=0,Lo=65536`). PoC: `TestPoC_HighPartAmbiguous`. | confirmed, high/medium |

Partition / split with a part too loosely bounded (V-R6).
