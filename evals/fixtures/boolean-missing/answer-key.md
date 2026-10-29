# Answer key — boolean-missing fixture

Fixture: `testdata/boolean-missing` (gnark v0.14.0, Groth16, BN254). Match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| P1 | `circuit/circuit.go` Define | `FlagA` and `FlagB` are combined as booleans (`Granted = FlagA*FlagB`) but never asserted boolean. | **High soundness.** `Granted == 1` is satisfied with non-boolean flags such as `2` and `1/2`, so access is granted though neither flag is a genuine `1`. PoC: `TestPoC_NonBooleanFlags`. | confirmed, high/medium |

Boolean algebra on values that are not proven boolean (V-G2).
