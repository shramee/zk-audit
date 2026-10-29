# Answer key — adv-emulated advisory replay

Fixture: `testdata/adv-emulated`, a gnark **v0.16.1** module using
`std/math/emulated`. **Requires Go >= 1.25.7** (gnark v0.16.1 declares it), so
it does not build or run under the default Go 1.24 toolchain; `make fixtures`
and the eval scaffold download it via `GOTOOLCHAIN` when a 1.25+ toolchain is
reachable. It was built and vetted here under `GOTOOLCHAIN=go1.25.7`.

| Id | Source | Expected |
|---|---|---|
| A1 | v0.16.1 is `< v0.16.2`, the fix for **GHSA-3mvx-pp85-pm65** (eleven std-library soundness issues in emulated arithmetic, GLV, uints lookups, pairing). Phase 0 must report it. | needs_validation / confirmed, critical |
| A2 | The circuit multiplies emulated elements, exercising the affected emulated-arithmetic path. | confirmed / needs_validation / lead / hardening |

No executed exploit PoC: the defect is in gnark's std library, documented by the
GHSA. Phase 0 detection works from `go.mod` without building the module.
