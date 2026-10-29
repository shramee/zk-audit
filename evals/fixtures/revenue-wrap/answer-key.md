# Answer key — revenue-wrap fixture

Fixture: `testdata/revenue-wrap` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize revenue-wrap <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| F1 | `circuit/circuit.go` Define | `Price` and `Quantity` are each bounded to 128 bits, then multiplied with `api.Mul` (field multiplication) and the product bound to `Revenue`. | **High soundness.** A 128x128-bit product is up to 256 bits and wraps the 254-bit BN254 scalar field, so `Revenue` is the product modulo r, not the integer product. A prover presents factors whose true product exceeds r and publishes a `Revenue` strictly below it. PoC: `TestPoC_RevenueWraps`. | confirmed, high/medium |

A product that must hold as an integer is checked in the native field (V-F6).
