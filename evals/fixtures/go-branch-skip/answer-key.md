# Answer key — go-branch-skip fixture

Fixture: `testdata/go-branch-skip` (gnark v0.14.0, Groth16, BN254). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| S1 | `circuit/circuit.go` Define | The quorum assertion is inside `if len(c.Approvals) > 0`, a Go branch on the compile-time slice length. | **High soundness.** Go code in `Define` runs once at compile time; the deployed shape compiles `Approvals` empty, so the branch is never emitted and `Granted`/`Threshold` are unconstrained — authorization passes with no approvals. PoC: `TestPoC_QuorumSkipped` (empty-shape attack vs a non-empty control that enforces the quorum). | confirmed, high/medium |

Go control flow on a (compile-time) value drops a constraint (V-S1).
