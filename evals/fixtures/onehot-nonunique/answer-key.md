# Answer key — onehot-nonunique fixture

Fixture: `testdata/onehot-nonunique` (gnark v0.14.0, Groth16, BN254). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| G1 | `circuit/circuit.go` Define | The selector bits are asserted boolean, but their sum is never constrained to 1. | **High soundness.** A prover activates several rows at once, so `Out` is their sum rather than one table entry. PoC: `TestPoC_MultiSelect` (rows 0+3 give Out=50). | confirmed, high/medium |

One-hot / index decoding without uniqueness (V-G3).
