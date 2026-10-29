# Answer key — adv-commit advisory replay

Fixture: `testdata/adv-commit`, a gnark **v0.10.0** module that calls
`frontend.Committer.Commit` on a private witness.

| Id | Source | Expected |
|---|---|---|
| A1 | v0.10.0 is `< v0.11.0`, the fix for **GHSA-9xcg-3q8v-7fq6 / CVE-2024-45040** (commitments to private witnesses are not hiding) and **GHSA-q3hw-3gm4-w5cr / CVE-2024-45039** (Groth16 unsound with more than one commitment). Phase 0 must report both. | needs_validation / confirmed |
| A2 | The circuit commits to a private `Secret`, exercising the affected commitment extension. | confirmed / needs_validation / lead |

No executed PoC: the defect is in gnark's commitment backend, documented by the
GHSAs.
