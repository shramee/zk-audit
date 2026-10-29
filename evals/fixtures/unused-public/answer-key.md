# Answer key — unused-public fixture

Fixture: `testdata/unused-public` (gnark v0.14.0, Groth16, BN254). Match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| P1 | `circuit/circuit.go` Define | `Epoch` is a public input, but no constraint ever reads it. | **High soundness.** The prover sets `Epoch` freely, so one ticket is valid in every epoch (cross-epoch replay). PoC: `TestPoC_EpochUnbound`. | confirmed, high/medium |

Public input that no constraint uses (V-PI2).
