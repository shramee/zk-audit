# gnark versions and advisories

Phase 0 matches the gnark version pinned in each `go.mod` against this table.
Any match is a finding candidate on its own: report it with the required action,
even if no circuit code is reviewed. The `gnark-inventory detect` command embeds
the JSON block at the end of this file; `gnark-inventory lint-kb` and a unit test
fail if the two differ.

Ranges use Go module semantics. A pseudo-version such as
`v0.16.4-0.20261001…` sorts **before** `v0.16.4`, so it is still affected by
advisories fixed in v0.16.4. A `replace` to a local path or a fork gives no
reliable version: the tool reports every advisory as `possibly_affected`, and the
report puts the version question under **Needs validation**.

## Table

| Advisory | Aliases | Severity | Class | Affected | Component | Regenerate keys | Verified in OSV |
|---|---|---|---|---|---|---|---|
| [GHSA-7fx8-hmgc-82jp](https://github.com/Consensys/gnark/security/advisories/GHSA-7fx8-hmgc-82jp) | – | high | soundness | < v0.16.4 | std/algebra emulated scalar multiplication (fake-GLV); std/signature/ecdsa incl. P-256 | yes | **no** |
| [GHSA-3mvx-pp85-pm65](https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65) | – | critical | soundness | < v0.16.2 | std (emulated arithmetic, torus, GLV, uints lookups for SHA2/Keccak, pairing Miller loop, comb scalar mul) | yes | **no** |
| [GHSA-fwf3-jmp7-gmrj](https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj) | – | moderate | soundness | < v0.16.0 | std/algebra pairing G2 membership (IsOnTwist vs AssertIsOnTwist) | yes | **no** |
| [GHSA-9fvj-xqr2-xwg8](https://github.com/Consensys/gnark/security/advisories/GHSA-9fvj-xqr2-xwg8) | CVE-2025-58157, GO-2025-3929 | high | availability | >= v0.12.0, < v0.13.0 | fake-GLV scalar decomposition hint (gnark-crypto half-GCD) | no | yes |
| [GHSA-95v9-hv42-pwrj](https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj) | CVE-2025-57801, GO-2025-3912 | high | soundness | < v0.14.0 | std/signature/eddsa, std/signature/ecdsa | yes | yes |
| [GHSA-cph5-3pgr-c82g](https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g) | CVE-2024-50354, GO-2024-3244 | moderate | availability | < v0.11.1 | backend/groth16 and backend/plonk deserialization (VerifyingKey, Proof ReadFrom) | no | yes |
| [GHSA-q3hw-3gm4-w5cr](https://github.com/Consensys/gnark/security/advisories/GHSA-q3hw-3gm4-w5cr) | CVE-2024-45039, GO-2024-3122 | moderate | soundness | < v0.11.0 | backend/groth16 commitment extension (more than one commitment) | yes | yes |
| [GHSA-9xcg-3q8v-7fq6](https://github.com/Consensys/gnark/security/advisories/GHSA-9xcg-3q8v-7fq6) | CVE-2024-45040, GO-2024-3123 | high | privacy | < v0.11.0 | backend/groth16 commitment extension (commitments to private witnesses) | yes | yes |
| [GHSA-rjjm-x32p-m3f7](https://github.com/Consensys/gnark/security/advisories/GHSA-rjjm-x32p-m3f7) | GO-2023-2333 | low | soundness | < v0.9.2 | std/rangecheck (used by field emulation, ECDSA, recursion) | yes | yes |
| [GHSA-7p92-x423-vwj6](https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6) | GO-2023-2119 | critical | soundness | < v0.9.1 | PLONK Solidity verifier template (batch_verify_multi_points) | no | yes |
| [GHSA-498w-5j49-vqjg](https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg) | CVE-2023-44378, GO-2023-2098 | moderate | soundness | < v0.9.0 | frontend API Cmp / IsLess, bits.ToBinary / api.ToBinary at full width | yes | yes |

**Verified in OSV** = the row was checked against api.osv.dev on 2026-10-27.
Rows marked **no** come from `docs/research.md` because the advisory is not in
OSV and the advisory page was not reachable from the build environment.
Confirm them on the advisory page before quoting exact versions to a client.

## Required actions by class

- **soundness**: upgrade, then **recompile every affected circuit and rerun
  setup**. Old proving and verifying keys and every verifier contract exported
  from them remain vulnerable. A gnark bump without new keys fixes nothing
  on-chain.
- **privacy**: upgrade and regenerate keys. Proofs already published keep
  leaking whatever they leaked.
- **availability**: upgrade the prover or service. Circuits and keys are
  unaffected when the bug is in a hint or a decoder.

## What to report

For each match: the advisory id and URL, the module path and pinned version,
whether the affected component is reachable from this repository (grep the
component's package in the inventory: `std/signature/ecdsa`, `std/recursion`,
`frontend.Committer` and so on), and the action above. An advisory whose
component is not imported is still reported, at **Info**, because the same keys
may be reused by other circuits.

Also check:

- `gnark-crypto`: several fixes ship there (GHSA-9fvj is fixed by a
  gnark-crypto commit). Report its version next to gnark's.
- More than one gnark version across modules: the key-generation code and the
  prover may disagree.
- Go toolchain: gnark v0.15 and later need Go ≥ 1.25; v0.16.4 needs Go 1.26.

## Machine-readable table

```json
{
  "schema_version": "1",
  "package": "github.com/consensys/gnark",
  "sources": [
    "OSV database (https://api.osv.dev) for github.com/consensys/gnark, fetched 2026-10-27",
    "docs/research.md section 6 for advisories not present in OSV (verified: false)"
  ],
  "advisories": [
    {
      "id": "GHSA-7fx8-hmgc-82jp",
      "aliases": [],
      "severity": "high",
      "class": "soundness",
      "component": "std/algebra emulated scalar multiplication (fake-GLV); std/signature/ecdsa incl. P-256",
      "summary": "Fake-GLV scalar-multiplication hint result is not checked to be on the curve, which lets a prover forge ECDSA / P-256 verification in-circuit.",
      "introduced": "0",
      "fixed": "v0.16.4",
      "action": "Upgrade to v0.16.4 or later, recompile every affected circuit and regenerate proving and verifying keys; redeploy any verifier contract built from the old keys.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-7fx8-hmgc-82jp",
      "verified": false
    },
    {
      "id": "GHSA-3mvx-pp85-pm65",
      "aliases": [],
      "severity": "critical",
      "class": "soundness",
      "component": "std (emulated arithmetic, torus, GLV, uints lookups for SHA2/Keccak, pairing Miller loop, comb scalar mul)",
      "summary": "Eleven std-library issues where a hint output is consumed without a binding or range constraint (emulated carry not range-checked, unconstrained torus scale, unbound GLV sub-scalars, remainder vs runtime modulus, uints lookup key collision, Miller loop with Q = 0, comb top bit).",
      "introduced": "0",
      "fixed": "v0.16.2",
      "action": "Upgrade to v0.16.2 or later (v0.16.4 also fixes GHSA-7fx8), recompile affected circuits and regenerate keys and verifier contracts.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65",
      "verified": false
    },
    {
      "id": "GHSA-fwf3-jmp7-gmrj",
      "aliases": [],
      "severity": "moderate",
      "class": "soundness",
      "component": "std/algebra pairing G2 membership (IsOnTwist vs AssertIsOnTwist)",
      "summary": "A G2 subgroup / twist check is computed but its result is discarded, so points off the twist are accepted.",
      "introduced": "0",
      "fixed": "v0.16.0",
      "action": "Upgrade past v0.15.0, recompile affected circuits and regenerate keys. Research notes give the fix as 'after v0.15.0'; confirm the exact version on the advisory page.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj",
      "verified": false
    },
    {
      "id": "GHSA-9fvj-xqr2-xwg8",
      "aliases": ["CVE-2025-58157", "GO-2025-3929"],
      "severity": "high",
      "class": "availability",
      "component": "fake-GLV scalar decomposition hint (gnark-crypto half-GCD)",
      "summary": "The scalar decomposition used by fake-GLV converges very slowly for some inputs, so a prover that accepts untrusted witnesses can be stalled (denial of service).",
      "introduced": "v0.12.0",
      "fixed": "v0.13.0",
      "action": "Upgrade gnark to v0.13.0 or later, or upgrade gnark-crypto to a version with commit 56600883. No recompilation is needed: the bug is in a hint.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-9fvj-xqr2-xwg8",
      "verified": true
    },
    {
      "id": "GHSA-95v9-hv42-pwrj",
      "aliases": ["CVE-2025-57801", "GO-2025-3912"],
      "severity": "high",
      "class": "soundness",
      "component": "std/signature/eddsa, std/signature/ecdsa",
      "summary": "Signature scalar S is not checked to satisfy 0 <= S < order, so signatures are malleable; nullifiers or replay keys derived from (R, S) can be double-spent.",
      "introduced": "0",
      "fixed": "v0.14.0",
      "action": "Upgrade to v0.14.0 or later and recompile; never derive nullifiers or replay protection from signature bytes.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj",
      "verified": true
    },
    {
      "id": "GHSA-cph5-3pgr-c82g",
      "aliases": ["CVE-2024-50354", "GO-2024-3244"],
      "severity": "moderate",
      "class": "availability",
      "component": "backend/groth16 and backend/plonk deserialization (VerifyingKey, Proof ReadFrom)",
      "summary": "Deserializing a crafted verifying key or proof allocates attacker-chosen sizes and can exhaust memory.",
      "introduced": "0",
      "fixed": "v0.11.1",
      "action": "Upgrade to v0.11.1 or later (the Go vuln DB entry GO-2024-3244 lists v0.12.0); do not deserialize keys or proofs from untrusted sources without size limits.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g",
      "verified": true
    },
    {
      "id": "GHSA-q3hw-3gm4-w5cr",
      "aliases": ["CVE-2024-45039", "GO-2024-3122"],
      "severity": "moderate",
      "class": "soundness",
      "component": "backend/groth16 commitment extension (more than one commitment)",
      "summary": "The same sigma is used for the proof of knowledge of every Groth16 commitment, so a prover can fix all but one commitment before choosing the witness; Groth16 with more than one commitment is unsound.",
      "introduced": "0",
      "fixed": "v0.11.0",
      "action": "Upgrade to v0.11.0 or later, recompile, rerun setup and redeploy the verifier.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-q3hw-3gm4-w5cr",
      "verified": true
    },
    {
      "id": "GHSA-9xcg-3q8v-7fq6",
      "aliases": ["CVE-2024-45040", "GO-2024-3123"],
      "severity": "high",
      "class": "privacy",
      "component": "backend/groth16 commitment extension (commitments to private witnesses)",
      "summary": "Groth16 commitments to private witness values are binding but not hiding, so a verifier can confirm guesses of committed secrets; zero knowledge is lost.",
      "introduced": "0",
      "fixed": "v0.11.0",
      "action": "Upgrade to v0.11.0 or later, recompile, rerun setup and redeploy the verifier.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-9xcg-3q8v-7fq6",
      "verified": true
    },
    {
      "id": "GHSA-rjjm-x32p-m3f7",
      "aliases": ["GO-2023-2333"],
      "severity": "low",
      "class": "soundness",
      "component": "std/rangecheck (used by field emulation, ECDSA, recursion)",
      "summary": "The range checker did not account for a short top partition, so inputs up to 16 bits wider than requested were accepted.",
      "introduced": "0",
      "fixed": "v0.9.2",
      "action": "Upgrade to v0.9.2 or later and recompile.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-rjjm-x32p-m3f7",
      "verified": true
    },
    {
      "id": "GHSA-7p92-x423-vwj6",
      "aliases": ["GO-2023-2119"],
      "severity": "critical",
      "class": "soundness",
      "component": "PLONK Solidity verifier template (batch_verify_multi_points)",
      "summary": "The KZG batch-opening randomness was derived from only the first 32 bytes of the verifier state, so a third party can derive a different valid proof for the same public inputs (the 'Last Challenge' attack).",
      "introduced": "0",
      "fixed": "v0.9.1",
      "action": "Regenerate the PLONK Solidity verifier with v0.9.1 or later and redeploy it.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6",
      "verified": true
    },
    {
      "id": "GHSA-498w-5j49-vqjg",
      "aliases": ["CVE-2023-44378", "GO-2023-2098"],
      "severity": "moderate",
      "class": "soundness",
      "component": "frontend API Cmp / IsLess, bits.ToBinary / api.ToBinary at full width",
      "summary": "Full-width binary decomposition accepts both a and a + r, so Cmp / IsLess can prove a < b when a > b.",
      "introduced": "0",
      "fixed": "v0.9.0",
      "action": "Upgrade to v0.9.0 or later and recompile; on older versions use std/math/cmp with a known bound.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg",
      "verified": true
    }
  ]
}
```
