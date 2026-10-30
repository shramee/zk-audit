# Answer key — adv-cmp advisory replay

Fixture: `testdata/adv-cmp`, a gnark **v0.8.1** module that uses
`api.AssertIsLessOrEqual`.

| Id | Source | Expected |
|---|---|---|
| A1 | v0.8.1 is `< v0.9.0`, the fix for **GHSA-498w-5j49-vqjg / CVE-2023-44378** (full-width binary decomposition accepts both `a` and `a + r`, so `Cmp` / `IsLess` can prove `a < b` when `a > b`). Phase 0 must report it. | needs_validation / confirmed |
| A2 | The circuit uses `AssertIsLessOrEqual`, which on this release is the affected comparator. | confirmed / needs_validation / lead |

No executed PoC: the defect is in gnark's comparison gadget, documented by the
GHSA.
