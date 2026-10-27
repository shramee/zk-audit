# Design notes

Where the implementation deviates from `PLAN.md`, or makes a choice the plan
left open, it is recorded here with the reason.

## Packaging

- **Entry point name.** Claude Code namespaces plugin skills and commands as
  `/<plugin>:<name>`. The skill is named `zk-audit`, so the full form is
  `/zk-audit:zk-audit`; `/zk-audit` works where the runtime resolves
  unambiguous short names. `setup`, `recon` and `diff` are commands
  (`/zk-audit:setup` etc.) as in PLAN §7. `recon` and `diff` are also accepted
  as skill arguments (`/zk-audit recon`), as PLAN §3 shows.
- **No `allowed-tools` on the skill.** The skill needs Agent, Bash, Read, Write
  (output dir only) and AskUserQuestion. Restricting the list risks silently
  dropping a tool on another runtime, and the read-only rule is enforced by the
  agent prompts and agent `tools:` allowlists instead.
- **`references/severity.md` is folded into `judging.md`.** Severity and
  confidence are assigned in the same pass as the gates, so one file avoids
  drift between them.
- **Two extra reference files**: `companions.md` (detection and install
  commands for §6 companions, used by `/zk-audit:setup` and Phase 0) and
  `poc-templates.md` (the `PoC:` field of each vector names a template there).

## gnark-inventory

- **Module location.** As PLAN §7: `plugins/zk-audit/tools/gnark-inventory` is
  its own Go module (`go 1.24`). It depends only on `golang.org/x/tools`
  (`go/packages`), which is **vendored** so the tool builds offline. Hard rule
  8 of the skill (no network during an audit) would otherwise be broken by the
  first build.
- **Schemas are duplicated** inside the tool (`internal/schemas/*.json`) because
  `go:embed` cannot reach `../../schemas`. A unit test fails if the copies
  differ from `plugins/zk-audit/schemas/*.json`.
- **Advisory table.** The canonical machine-readable table is
  `internal/advisory/advisories.json` in the tool. `references/gnark-versions.md`
  carries the same JSON in a fenced block; a unit test fails if they differ.
- **Fallback loader.** If `go/packages` cannot type-check the target (missing
  dependencies, wrong toolchain), the tool falls back to `go/parser` and marks
  unresolved items (`resolved: false`). gnark ≥ v0.15 needs Go ≥ 1.25 and
  v0.16.4 needs Go 1.26, so type loading of a current gnark project needs a
  newer toolchain than the tool itself (`GOTOOLCHAIN=auto` handles this when
  the network allows it).

## Knowledge base facts that differ from `docs/research.md`

Advisory data was re-checked against the OSV database (api.osv.dev, fetched
2026-10-27) and the gnark source tree (`v0.16.4`, `audits/`):

- **GHSA-7p92-x423-vwj6** is the PLONK Solidity verifier deriving the
  KZG batch-opening randomness from only the first 32 bytes of state
  (`batch_verify_multi_points`). It is the bug the "Last Challenge" paper
  (eprint 2024/398) describes; the advisory text is quoted for accuracy.
- **Severities follow the GitHub advisory**: GHSA-498w (CVE-2023-44378) is
  Moderate, GHSA-9xcg (CVE-2024-45040) is High, GHSA-9fvj (CVE-2025-58157)
  affects v0.12.x only and is fixed in v0.13.0.
- **GHSA-cph5 / CVE-2024-50354**: the GHSA says fixed in v0.11.1, the Go vuln
  DB (GO-2024-3244) says v0.12.0. The table uses v0.11.1 and notes the
  discrepancy.
- **GHSA-3mvx-pp85-pm65, GHSA-7fx8-hmgc-82jp, GHSA-fwf3-jmp7-gmrj** are not
  in OSV and the GitHub advisory pages were not reachable from the build
  environment. Their rows use `docs/research.md` and are marked
  `"verified": false` in the machine-readable table. For GHSA-fwf3 the research
  notes say "fixed after v0.15.0"; the table uses v0.16.0 (the next release)
  and flags it.
- **zkSecurity gnark-std audit numbering** follows the report PDF in
  `gnark/audits/2024-05 - zksecurity - gnark std.pdf` (00 MultiCommitter …
  0b leaky abstraction), which differs from the order in `research.md`.
- **Emulated witness width.** In gnark v0.16.4, `emulated.Field` methods call
  `enforceWidthConditional` on non-internal elements, so witness limbs are
  width-checked on first use. The residual risks the footgun covers are: the
  value is not reduced below the modulus (`Reduce` vs `ReduceStrict` /
  `AssertIsInRange`) and direct use of `Element.Limbs` in native arithmetic,
  which bypasses the width check (zkSecurity 0b, "won't fix").
