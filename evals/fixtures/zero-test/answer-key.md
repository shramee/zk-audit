# Answer key — zero-test fixture

Fixture: `testdata/zero-test` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize zero-test <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| F1 | `circuit/circuit.go` Define | The inverse-based zero test computes `blocked = 1 - Value*inv` but omits the second standard constraint `Value*blocked == 0`, so `inv` is a free hint output. | **High soundness.** Without `Value*blocked == 0`, a prover forges `inv` (e.g. 0) so that a nonzero `Value` yields `blocked = 1`: any value can be reported as zero, defeating whatever the flag gates. PoC: `TestPoC_FalseZeroFlag`. | confirmed, high/medium |

Inverse/zero test missing its binding constraint (V-F2 / V-H1).
