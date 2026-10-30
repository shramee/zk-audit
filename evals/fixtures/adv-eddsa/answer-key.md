# Answer key — adv-eddsa advisory replay

Fixture: `testdata/adv-eddsa`, a gnark **v0.13.0** module that exercises
`std/signature/eddsa`. v0.13.0 predates the fix for the EdDSA/ECDSA scalar
malleability advisory.

## Expected

| Id | Source | Expected |
|---|---|---|
| A1 | `go.mod` pins gnark v0.13.0, which is `< v0.14.0`, the fix for **GHSA-95v9-hv42-pwrj / CVE-2025-57801** (signature scalar S not checked canonical → malleable EdDSA/ECDSA). Phase 0 must report it. | needs_validation or confirmed, high |
| A2 | The circuit derives a nullifier from the signature `S` component, and `std/signature/eddsa` on this release is the affected gadget, so the malleable signature yields a second valid nullifier (double spend). | confirmed / needs_validation / lead |

The advisory must be reported from the version alone (Phase 0). Because the
circuit uses the affected gadget and keys a nullifier on the signature, the
report should also locate the malleability reachability (A2). No executed PoC
is shipped: the defect is in gnark's std library, documented by the GHSA.
