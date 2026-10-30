# Answer key — merkle-sentinel fixture

Fixture: `testdata/merkle-sentinel` (gnark v0.14.0, Groth16, BN254). Audits run
on the sanitized copy from `evals/sanitize merkle-sentinel <scratch>`; match by
code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| M1 | `circuit/circuit.go` Define | The Merkle membership check never asserts `Leaf != 0`, and unused tree slots are the sentinel value 0. | **High soundness.** A prover proves membership of an empty slot (`Leaf = 0`) and so passes an authorization gated on tree membership without ever being added to the tree. PoC: `TestPoC_EmptySlotMember`. | confirmed, high/medium |

Empty-leaf sentinel accepted as a member (V-PS3).
