# Answer key — real-plonky2 (succinctlabs/gnark-plonky2-verifier, pre-fix)

Real repository, **not vendored**. The case scaffold fetches
`github.com/succinctlabs/gnark-plonky2-verifier` at the pre-fix commit
`89b5a01` (`v0.0.0-20231013210054-89b5a01e4b4b`, which pins gnark v0.9.0)
through the Go module proxy, cached under `.cache/`.

Ground truth is the **Veridise audit report `VAR_Succinct-V1.pdf`** shipped in
the repo's own `audits/` directory (the report audited commit `89b5a01`; all
three critical issues are marked Fixed in later commits). Only the three
critical under-constraint findings are scored here; the medium/low items are
out of scope for the quick profile.

| Id | Report | Location | Defect | Expected |
|---|---|---|---|---|
| R1 | V-SCT-VUL-001 (Critical) | `goldilocks/base.go` `Inverse()` | The hint-provided inverse is only constrained by `inverse*x == 1`; it is never range-checked into the Goldilocks field, so `inv(x) + k*MODULUS` are all valid solutions. | confirmed, critical |
| R2 | V-SCT-VUL-002 (Critical) | `goldilocks/base.go` `Reduce()` | The reduce hint's `(quotient, remainder)` are range-checked but never constrained by `MODULUS*quotient + remainder == x`, so a prover reduces `x` to any Goldilocks element. | confirmed, critical |
| R3 | V-SCT-VUL-003 (Critical) | `goldilocks/base.go` `ReduceWithMaxBits()` | Same missing `== x` constraint as R2. | confirmed, critical |
| R4 | dependency | `go.mod` | gnark v0.9.0 is `< v0.9.2` (GHSA-rjjm rangecheck) and predates the commitment/eddsa fixes; Phase 0 should flag it. | needs_validation / confirmed |

Fix commits (from the report): R1 → `9e96393`, R2/R3 → `297a820`. No executed
PoC is shipped for the real repo; the ground truth is the public report.
