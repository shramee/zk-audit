# gnark versions and advisories

Phase 0 matches the gnark and gnark-crypto versions pinned in each `go.mod`
against this table.
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

The table is as of **2026-10-29** (`as_of` in the JSON block). `gnark-inventory
advisories` prints it offline with that date; `gnark-inventory advisories --osv`
compares it with the OSV database (network, ask first; see below).

| Advisory | Module | Aliases | Severity | Class | Affected | Component | Regenerate keys | Verified |
|---|---|---|---|---|---|---|---|---|
| [GHSA-7fx8-hmgc-82jp](https://github.com/Consensys/gnark/security/advisories/GHSA-7fx8-hmgc-82jp) | gnark | – | high | soundness | < v0.16.4 | std/algebra emulated scalar multiplication (fake-GLV); std/signature/ecdsa incl. P-256 | yes | fix in source |
| [GHSA-3mvx-pp85-pm65](https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65) | gnark | – | critical | soundness | < v0.16.2 | std (emulated arithmetic, torus, GLV, uints lookups for SHA2/Keccak, pairing Miller loop, comb scalar mul) | yes | fix in source |
| [GHSA-fwf3-jmp7-gmrj](https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj) | gnark | – | moderate | soundness | < v0.16.0 | std/algebra pairing G2 membership (IsOnTwist vs AssertIsOnTwist) | yes | fix in source |
| [GHSA-9fvj-xqr2-xwg8](https://github.com/Consensys/gnark/security/advisories/GHSA-9fvj-xqr2-xwg8) | gnark | CVE-2025-58157, GO-2025-3929 | high | availability | >= v0.12.0, < v0.13.0 | fake-GLV scalar decomposition hint (gnark-crypto half-GCD) | no | OSV |
| [GHSA-95v9-hv42-pwrj](https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj) | gnark | CVE-2025-57801, GO-2025-3912 | high | soundness | < v0.14.0 | std/signature/eddsa, std/signature/ecdsa | yes | OSV |
| [GHSA-cph5-3pgr-c82g](https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g) | gnark | CVE-2024-50354, GO-2024-3244 | moderate | availability | < v0.11.1 | backend/groth16 and backend/plonk deserialization (VerifyingKey, Proof ReadFrom) | no | OSV |
| [GHSA-q3hw-3gm4-w5cr](https://github.com/Consensys/gnark/security/advisories/GHSA-q3hw-3gm4-w5cr) | gnark | CVE-2024-45039, GO-2024-3122 | moderate | soundness | < v0.11.0 | backend/groth16 commitment extension (more than one commitment) | yes | OSV |
| [GHSA-9xcg-3q8v-7fq6](https://github.com/Consensys/gnark/security/advisories/GHSA-9xcg-3q8v-7fq6) | gnark | CVE-2024-45040, GO-2024-3123 | high | privacy | < v0.11.0 | backend/groth16 commitment extension (commitments to private witnesses) | yes | OSV |
| [GHSA-rjjm-x32p-m3f7](https://github.com/Consensys/gnark/security/advisories/GHSA-rjjm-x32p-m3f7) | gnark | GO-2023-2333 | low | soundness | < v0.9.2 | std/rangecheck (used by field emulation, ECDSA, recursion) | yes | OSV |
| [GHSA-7p92-x423-vwj6](https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6) | gnark | GO-2023-2119 | critical | soundness | < v0.9.1 | PLONK Solidity verifier template (batch_verify_multi_points) | no | OSV |
| [GHSA-498w-5j49-vqjg](https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg) | gnark | CVE-2023-44378, GO-2023-2098 | moderate | soundness | < v0.9.0 | frontend API Cmp / IsLess, bits.ToBinary / api.ToBinary at full width | yes | OSV |
| [GHSA-fj2x-735w-74vq](https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-fj2x-735w-74vq) | gnark-crypto | GO-2025-4087 | high | availability | >= v0.9.1, < v0.18.1; >= v0.19.0, < v0.19.2 | gnark-crypto Vector.ReadFrom (field-element vector deserialization, reached when gnark reads proofs, keys and witnesses) | no | OSV |
| [GHSA-fr8m-434r-g3xp](https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-fr8m-434r-g3xp) | gnark-crypto | CVE-2023-44273, GHSA-9xfq-8j3r-xp5g, GO-2023-2096, GO-2025-4027 | moderate | availability | < v0.12.0 | gnark-crypto native ECDSA and EdDSA signature deserialization (SetBytes) | no | OSV |
| [GHSA-pffg-92cg-xf5c](https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-pffg-92cg-xf5c) | gnark-crypto | GO-2023-2101 | low | correctness | < v0.12.1 | gnark-crypto pairing target group GT ExpGLV | no | OSV |

**Verified**: **OSV** = the id and range match the OSV record (api.osv.dev,
2026-10-29). **fix in source** = OSV and the Go vulnerability database do not
list the advisory and its GitHub page was not reachable, so the fix was
located in the released gnark source in the Go module cache; the `evidence`
field names the file and version:

- GHSA-7fx8-hmgc-82jp: v0.16.4 `std/algebra/emulated/sw_emulated/point.go`
  `scalarMulFakeGLV` adds `AssertIsOnCurve` on the hinted result; v0.16.3 does
  not. The fake-GLV path exists from v0.12.0; the row keeps `introduced: 0`.
- GHSA-3mvx-pp85-pm65: v0.16.0 (GLV sub-scalar range checks, Miller-loop
  return value no longer discarded) and v0.16.2 (`field_smallmul.go` binds
  each quotient, `sha3.go` bounds the padding quotient). v0.16.3 adds one more
  per-quotient range check in the same small-field path that no published
  advisory names: recommend v0.16.4.
- GHSA-fwf3-jmp7-gmrj: v0.16.0 `std/algebra/emulated/sw_bn254` and
  `sw_bls12381` `precomputations.go` call `AssertIsOnTwist`; v0.12.0 to
  v0.15.0 call `IsOnTwist` and discard the result.

The advisory text of these three (exact affected range, severity) is still
unconfirmed: quote the fix version, and say the range comes from the source.

### Freshness check (`--osv`)

```bash
{skill}/scripts/gnark-inventory advisories --repo <repo> --osv
```

It sends the module names and pinned versions of gnark and gnark-crypto (no
source, no repository name) to `https://api.osv.dev/v1/query` and lists ids
OSV has that the table lacks, ids whose fixed version differs, and table rows
OSV does not list (expected for the three rows above). It is network access:
ask the user first (hard rules 4 and 8), and never run it in the audit
sandbox. Without `--osv` the command is offline and prints `table as of
<date>`. A new id it reports is a finding candidate like any table match:
read the OSV record, then report it with its fixed version.

## Required actions by class

- **soundness**: upgrade, then **recompile every affected circuit and rerun
  setup**. Old proving and verifying keys and every verifier contract exported
  from them remain vulnerable. A gnark bump without new keys fixes nothing
  on-chain.
- **privacy**: upgrade and regenerate keys. Proofs already published keep
  leaking whatever they leaked.
- **availability**: upgrade the prover or service. Circuits and keys are
  unaffected when the bug is in a hint or a decoder.
- **correctness**: a native (off-circuit) computation can return a wrong
  value. Upgrade, and recompute anything derived with the affected function
  (reference values, test vectors, native witnesses).

## What to report

For each match: the advisory id and URL, the module path and pinned version,
whether the affected component is reachable from this repository (grep the
component's package in the inventory: `std/signature/ecdsa`, `std/recursion`,
`frontend.Committer` and so on), and the action above. An advisory whose
component is not imported is still reported, at **Info**, because the same keys
may be reused by other circuits.

Also check:

- `gnark-crypto`: its own advisories are in the table (module
  `gnark-crypto`) and `detect` matches them against the gnark-crypto
  version in `go.mod`; several gnark fixes also ship there (GHSA-9fvj is
  fixed by a gnark-crypto commit). Report its version next to gnark's.
- More than one gnark version across modules: the key-generation code and the
  prover may disagree.
- Go toolchain: gnark v0.15 and later need Go ≥ 1.25.7; v0.16.4 needs Go
  1.26.8 (version matrix below; `gnark-inventory preflight` checks it).

## Version support matrix

`test/versions/run --foundry` in the zk-audit repository (not shipped with
the skill) runs each Go PoC template, the per-gadget harness, a Foundry
test against the Groth16 verifier gnark exports and the inventory against
each release, with the Go toolchain the release's `go` directive needs
(`GOTOOLCHAIN=auto`). Last run: 2026-10-29. CI reruns three columns.

| Template / check | v0.8.1 | v0.10.0 | v0.11.0 | v0.12.0 | v0.13.0 | v0.14.0 | v0.15.0 | v0.16.4 |
|---|---|---|---|---|---|---|---|---|
| T-HINT-OVERRIDE (`ccs.Solve`, `solver.OverrideHint`) | API differs (1) | works | works | works | works | works | works | works |
| T-PROVE-VERIFY, Groth16 | API differs (1) | works | works | works | works | works | works | works |
| T-PROVE-VERIFY, PLONK (`unsafekzg.NewSRS`) | API differs (1) | works | works | works | works | works | works | works |
| T-ASSERT-OVERRIDE (`test.WithSolverOpts`, `NoTestEngine`) | API differs (1) | works | works | works | works | works | works | works |
| T-ASSERT-OVERRIDE on the test engine (`test.WithReplacementHint`) | API differs (1) | API differs (2) | API differs (2) | API differs (2) | API differs (2) | API differs (2) | works | works |
| T-ALIAS (`bits.OmitModulusCheck`, hint by name) | API differs (1) | works | works | works | works | works | works | works |
| T-INVALID-ASSIGNMENT | works | works | works | works | works | works | works | works |
| T-COMPLETENESS (`ccs.Solve`) | API differs (3) | works | works | works | works | works | works | works |
| T-LINKAGE (native and in-circuit MiMC agree) | works | works | works | works | works | works | works | works |
| T-GADGET-HARNESS (`gnark-inventory harness` output compiles) | API differs (1) | works | works | works | works | works | works | works |
| T-FOUNDRY-VERIFIER (exported verifier, honest proof, wrong input rejected) | works (4) | works (5) | works (5) | works (5) | works (5) | works (5) | works (6) | works (6) |
| Inventory, tool built with the local Go 1.24 | types | types | types | types | types | types | syntax (7) | syntax (7) |
| Inventory with `ZK_AUDIT_GO` = the toolchain gnark needs | types | types | types | types | types | types | types (Go 1.25.7) | types (Go 1.26.8) |
| gnark `go` directive | 1.18 | 1.21 | 1.22 | 1.22 | 1.23.0 | 1.24.0 | 1.25.7 | 1.26.8 |

1. gnark < v0.9 has no `constraint/solver` package: no `OverrideHint`,
   `GetHintID`, `WithHints` there or `ccs.Solve`. Hints are
   `backend/hint.Function`, registered with `hint.Register` or passed with
   `backend.WithHints`, and a hint is identified by its function name, so
   it cannot be replaced at solve time. On v0.8 use T-INVALID-ASSIGNMENT,
   or T-CONSTRAINT-MODEL with the hint copied into a model circuit.
2. `test.WithReplacementHint` exists from v0.15.0. Before, use
   `test.WithSolverOpts(solver.OverrideHint(...))` with `test.NoTestEngine()`.
3. v0.8: `ccs.IsSolved(witness)` instead of `ccs.Solve`.
4. `verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[N] input) returns (bool)`.
5. `verifyProof(uint256[8] proof, uint256[N] input)`, reverts on an invalid proof.
6. `verifyProof(bytes proof, uint256[N] input)`, reverts; without
   commitments `proof` is the eight words packed (256 bytes).
   `gnark-inventory verifier abi` knows all three forms.
7. The tool's type checker refuses packages whose `go` directive is newer
   than the Go it was built with ("package requires newer Go version").
   `gnark-inventory preflight` prints a cached toolchain as `use_go`; prefix
   the inventory command with `ZK_AUDIT_GO=<use_go>` and the wrapper builds
   the tool with that toolchain and puts it first on `PATH`.

## Machine-readable table

```json
{
  "schema_version": "2",
  "as_of": "2026-10-29",
  "packages": ["github.com/consensys/gnark", "github.com/consensys/gnark-crypto"],
  "sources": [
    "OSV database (https://api.osv.dev, POST /v1/query) for github.com/consensys/gnark and github.com/consensys/gnark-crypto, fetched 2026-10-29; the Go vulnerability database index (https://vuln.go.dev/index/modules.json) lists the same GO- ids",
    "gnark release sources in the Go module cache (proxy.golang.org) v0.12.0 to v0.16.4 and their CHANGELOG.md, for the three gnark advisories OSV does not list; their GitHub advisory pages were not reachable from the build environment (verified_by: source)",
    "docs/research.md section 6 for the ids, components and summaries of those three advisories"
  ],
  "advisories": [
    {
      "id": "GHSA-7fx8-hmgc-82jp",
      "aliases": [],
      "package": "github.com/consensys/gnark",
      "severity": "high",
      "class": "soundness",
      "component": "std/algebra emulated scalar multiplication (fake-GLV); std/signature/ecdsa incl. P-256",
      "summary": "Fake-GLV scalar-multiplication hint result is not checked to be on the curve, which lets a prover forge ECDSA / P-256 verification in-circuit.",
      "introduced": "0",
      "fixed": "v0.16.4",
      "action": "Upgrade to v0.16.4 or later, recompile every affected circuit and regenerate proving and verifying keys; redeploy any verifier contract built from the old keys.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-7fx8-hmgc-82jp",
      "verified": true,
      "verified_by": "source",
      "evidence": "Fix located: gnark v0.16.4 std/algebra/emulated/sw_emulated/point.go scalarMulFakeGLV adds c.AssertIsOnCurve on the hinted result R (comment: 'R is prover-supplied ... AssertIsOnCurve'); v0.16.3 lacks it. The fake-GLV path first appears in v0.12.0 (absent from v0.11.0); the row keeps introduced 0 because the advisory text could not be read. Not in OSV or the Go vulnerability database on 2026-10-29."
    },
    {
      "id": "GHSA-3mvx-pp85-pm65",
      "aliases": [],
      "package": "github.com/consensys/gnark",
      "severity": "critical",
      "class": "soundness",
      "component": "std (emulated arithmetic, torus, GLV, uints lookups for SHA2/Keccak, pairing Miller loop, comb scalar mul)",
      "summary": "Eleven std-library issues where a hint output is consumed without a binding or range constraint (emulated carry not range-checked, unconstrained torus scale, unbound GLV sub-scalars, remainder vs runtime modulus, uints lookup key collision, Miller loop with Q = 0, comb top bit).",
      "introduced": "0",
      "fixed": "v0.16.2",
      "action": "Upgrade to v0.16.4 (v0.16.2 is the advisory's fix; v0.16.3 adds a related quotient range check and v0.16.4 fixes GHSA-7fx8), recompile affected circuits and regenerate keys and verifier contracts.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65",
      "verified": true,
      "verified_by": "source",
      "evidence": "Fixes located: v0.16.0 CHANGELOG 'GLV subscalar range checks' (#1778) and 'do not discard returned value in Miller loop precomputelines' (#1786); v0.16.2 std/math/emulated/field_smallmul.go range-checks each quotient in smallCheckZero ('Bind quotient in smallCheckZero') and std/hash/sha3/sha3.go bounds the Euclidean quotient ('sha3: Bind the Euclidean relation length'). v0.16.3 adds a further per-quotient range check in the same small-field multiplication ('range check quotient for small fields') that no published advisory names. Not in OSV or the Go vulnerability database on 2026-10-29."
    },
    {
      "id": "GHSA-fwf3-jmp7-gmrj",
      "aliases": [],
      "package": "github.com/consensys/gnark",
      "severity": "moderate",
      "class": "soundness",
      "component": "std/algebra pairing G2 membership (IsOnTwist vs AssertIsOnTwist)",
      "summary": "A G2 subgroup / twist check is computed but its result is discarded, so points off the twist are accepted.",
      "introduced": "0",
      "fixed": "v0.16.0",
      "action": "Upgrade to v0.16.0 or later (v0.16.4 for every gnark fix), recompile affected circuits and regenerate keys.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj",
      "verified": true,
      "verified_by": "source",
      "evidence": "Fix located: gnark v0.16.0 std/algebra/emulated/sw_bn254/precomputations.go and sw_bls12381/precomputations.go call pr.AssertIsOnTwist(&Qaff) where v0.12.0 to v0.15.0 call IsOnTwist and discard the result (v0.11.0 and earlier have no twist check there at all). Not in OSV or the Go vulnerability database on 2026-10-29."
    },
    {
      "id": "GHSA-9fvj-xqr2-xwg8",
      "aliases": ["CVE-2025-58157", "GO-2025-3929"],
      "package": "github.com/consensys/gnark",
      "severity": "high",
      "class": "availability",
      "component": "fake-GLV scalar decomposition hint (gnark-crypto half-GCD)",
      "summary": "The scalar decomposition used by fake-GLV converges very slowly for some inputs, so a prover that accepts untrusted witnesses can be stalled (denial of service).",
      "introduced": "v0.12.0",
      "fixed": "v0.13.0",
      "action": "Upgrade gnark to v0.13.0 or later, or upgrade gnark-crypto to a version with commit 56600883. No recompilation is needed: the bug is in a hint.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-9fvj-xqr2-xwg8",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-9fvj-xqr2-xwg8 matches the range."
    },
    {
      "id": "GHSA-95v9-hv42-pwrj",
      "aliases": ["CVE-2025-57801", "GO-2025-3912"],
      "package": "github.com/consensys/gnark",
      "severity": "high",
      "class": "soundness",
      "component": "std/signature/eddsa, std/signature/ecdsa",
      "summary": "Signature scalar S is not checked to satisfy 0 <= S < order, so signatures are malleable; nullifiers or replay keys derived from (R, S) can be double-spent.",
      "introduced": "0",
      "fixed": "v0.14.0",
      "action": "Upgrade to v0.14.0 or later and recompile; never derive nullifiers or replay protection from signature bytes.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-95v9-hv42-pwrj matches the range."
    },
    {
      "id": "GHSA-cph5-3pgr-c82g",
      "aliases": ["CVE-2024-50354", "GO-2024-3244"],
      "package": "github.com/consensys/gnark",
      "severity": "moderate",
      "class": "availability",
      "component": "backend/groth16 and backend/plonk deserialization (VerifyingKey, Proof ReadFrom)",
      "summary": "Deserializing a crafted verifying key or proof allocates attacker-chosen sizes and can exhaust memory.",
      "introduced": "0",
      "fixed": "v0.11.1",
      "action": "Upgrade to v0.11.1 or later (the Go vuln DB entry GO-2024-3244 lists v0.12.0); do not deserialize keys or proofs from untrusted sources without size limits.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-cph5-3pgr-c82g matches the range (the Go vulnerability database entry GO-2024-3244 gives the fix as v0.12.0)."
    },
    {
      "id": "GHSA-q3hw-3gm4-w5cr",
      "aliases": ["CVE-2024-45039", "GO-2024-3122"],
      "package": "github.com/consensys/gnark",
      "severity": "moderate",
      "class": "soundness",
      "component": "backend/groth16 commitment extension (more than one commitment)",
      "summary": "The same sigma is used for the proof of knowledge of every Groth16 commitment, so a prover can fix all but one commitment before choosing the witness; Groth16 with more than one commitment is unsound.",
      "introduced": "0",
      "fixed": "v0.11.0",
      "action": "Upgrade to v0.11.0 or later, recompile, rerun setup and redeploy the verifier.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-q3hw-3gm4-w5cr",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-q3hw-3gm4-w5cr matches the range."
    },
    {
      "id": "GHSA-9xcg-3q8v-7fq6",
      "aliases": ["CVE-2024-45040", "GO-2024-3123"],
      "package": "github.com/consensys/gnark",
      "severity": "high",
      "class": "privacy",
      "component": "backend/groth16 commitment extension (commitments to private witnesses)",
      "summary": "Groth16 commitments to private witness values are binding but not hiding, so a verifier can confirm guesses of committed secrets; zero knowledge is lost.",
      "introduced": "0",
      "fixed": "v0.11.0",
      "action": "Upgrade to v0.11.0 or later, recompile, rerun setup and redeploy the verifier.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-9xcg-3q8v-7fq6",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-9xcg-3q8v-7fq6 matches the range."
    },
    {
      "id": "GHSA-rjjm-x32p-m3f7",
      "aliases": ["GO-2023-2333"],
      "package": "github.com/consensys/gnark",
      "severity": "low",
      "class": "soundness",
      "component": "std/rangecheck (used by field emulation, ECDSA, recursion)",
      "summary": "The range checker did not account for a short top partition, so inputs up to 16 bits wider than requested were accepted.",
      "introduced": "0",
      "fixed": "v0.9.2",
      "action": "Upgrade to v0.9.2 or later and recompile.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-rjjm-x32p-m3f7",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-rjjm-x32p-m3f7 matches the range (GO-2023-2333 gives the fix as the pseudo-version v0.9.2-0.20231110170422-f528807119e9)."
    },
    {
      "id": "GHSA-7p92-x423-vwj6",
      "aliases": ["GO-2023-2119"],
      "package": "github.com/consensys/gnark",
      "severity": "critical",
      "class": "soundness",
      "component": "PLONK Solidity verifier template (batch_verify_multi_points)",
      "summary": "The KZG batch-opening randomness was derived from only the first 32 bytes of the verifier state, so a third party can derive a different valid proof for the same public inputs (the 'Last Challenge' attack).",
      "introduced": "0",
      "fixed": "v0.9.1",
      "action": "Regenerate the PLONK Solidity verifier with v0.9.1 or later and redeploy it.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-7p92-x423-vwj6 matches the range."
    },
    {
      "id": "GHSA-498w-5j49-vqjg",
      "aliases": ["CVE-2023-44378", "GO-2023-2098"],
      "package": "github.com/consensys/gnark",
      "severity": "moderate",
      "class": "soundness",
      "component": "frontend API Cmp / IsLess, bits.ToBinary / api.ToBinary at full width",
      "summary": "Full-width binary decomposition accepts both a and a + r, so Cmp / IsLess can prove a < b when a > b.",
      "introduced": "0",
      "fixed": "v0.9.0",
      "action": "Upgrade to v0.9.0 or later and recompile; on older versions use std/math/cmp with a known bound.",
      "regenerate_keys": true,
      "url": "https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-498w-5j49-vqjg matches the range."
    },
    {
      "id": "GHSA-fj2x-735w-74vq",
      "aliases": ["GO-2025-4087"],
      "package": "github.com/consensys/gnark-crypto",
      "severity": "high",
      "class": "availability",
      "component": "gnark-crypto Vector.ReadFrom (field-element vector deserialization, reached when gnark reads proofs, keys and witnesses)",
      "summary": "A 4-byte length read from untrusted input sizes an allocation without a bound, so a crafted proof or key can make a verifier or prover allocate up to 128 GB and crash.",
      "introduced": "v0.9.1",
      "fixed": "v0.18.1",
      "extra_ranges": [
        {
          "introduced": "v0.19.0",
          "fixed": "v0.19.2"
        }
      ],
      "action": "Upgrade gnark-crypto to v0.18.1 (0.18 line) or v0.19.2 or later; never deserialize proofs, keys or witnesses from untrusted sources without a size limit. Circuits and keys are unaffected.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-fj2x-735w-74vq",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-fj2x-735w-74vq (two ranges) and GO-2025-4087."
    },
    {
      "id": "GHSA-fr8m-434r-g3xp",
      "aliases": ["CVE-2023-44273", "GHSA-9xfq-8j3r-xp5g", "GO-2023-2096", "GO-2025-4027"],
      "package": "github.com/consensys/gnark-crypto",
      "severity": "moderate",
      "class": "availability",
      "component": "gnark-crypto native ECDSA and EdDSA signature deserialization (SetBytes)",
      "summary": "Deserialization did not check that R and s lie in [1, n-1]: zero values reach a nil-pointer dereference (denial of service) and serialized signatures are malleable, so off-circuit replay keys built from signature bytes are not unique.",
      "introduced": "0",
      "fixed": "v0.12.0",
      "action": "Upgrade gnark-crypto to v0.12.0 or later; never key replay protection on serialized signature bytes.",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-fr8m-434r-g3xp",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-fr8m-434r-g3xp and its aliases GO-2023-2096 and GO-2025-4027."
    },
    {
      "id": "GHSA-pffg-92cg-xf5c",
      "aliases": ["GO-2023-2101"],
      "package": "github.com/consensys/gnark-crypto",
      "severity": "low",
      "class": "correctness",
      "component": "gnark-crypto pairing target group GT ExpGLV",
      "summary": "GLV exponentiation in GT can return a wrong result when the exponent is larger than the group order r; Exp and ExpCyclotomic and the G1 / G2 GLV methods are not affected.",
      "introduced": "0",
      "fixed": "v0.12.1",
      "action": "Upgrade gnark-crypto to v0.12.1 or later; re-derive any value computed natively with GT ExpGLV (for example test vectors or off-circuit references).",
      "regenerate_keys": false,
      "url": "https://github.com/Consensys/gnark-crypto/security/advisories/GHSA-pffg-92cg-xf5c",
      "verified": true,
      "verified_by": "osv",
      "evidence": "OSV record GHSA-pffg-92cg-xf5c and GO-2023-2101."
    }
  ]
}
```
