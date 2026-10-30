# Answer key — cmp-bound fixture

Fixture: `testdata/cmp-bound` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize cmp-bound <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| R1 | `circuit/circuit.go` Define | `NewBoundedComparator(2^32)` assumes `|Spend-Balance| <= 2^32`, but `Spend` and `Balance` are never range-checked. | **High soundness.** An operand near the field order breaks the comparator's precondition: `Spend = r-1` passes `Spend <= Balance` against `Balance = 0`, so a prover "spends" an astronomically large amount. PoC: `TestPoC_ComparatorPreconditionBroken`. | confirmed, high/medium |

Bounded comparator used outside its precondition (V-R4).
