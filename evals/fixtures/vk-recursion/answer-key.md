# Answer key — vk-recursion fixture

Fixture: `testdata/vk-recursion` (gnark v0.14.0, std/recursion/groth16 (emulated BN254)). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| CM1 | `circuit/circuit.go` Define | `VerifyingKey` is a private witness and is never bound to a trusted key (no hash-against-a-public-commitment, not a hardcoded constant). | **Critical soundness.** A prover supplies the verifying key of a trivially satisfiable circuit together with a matching inner proof, so the aggregator verifies an arbitrary statement. PoC: **not executed** — compiling an in-circuit BN254 Groth16 verifier and forging a second VK is too heavy for the eval harness; the under-constraint is located structurally and the shape is confirmed by code review. | confirmed, critical/high |

Inner verifying key is a free witness (V-CM4).
