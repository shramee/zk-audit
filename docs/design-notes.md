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

- **Module location.** `plugins/zk-audit/skills/zk-audit/tools/gnark-inventory` is
  its own Go module (`go 1.24`). It depends only on `golang.org/x/tools`
  (`go/packages`), which is **vendored** so the tool builds offline. Hard rule
  8 of the skill (no network during an audit) would otherwise be broken by the
  first build.
- **Schemas are duplicated** inside the tool (`internal/validate/schemas/*.json`) because
  `go:embed` cannot reach `../../schemas`. A unit test fails if the copies
  differ from `plugins/zk-audit/skills/zk-audit/schemas/*.json`.
- **Advisory table.** The canonical machine-readable table is
  `internal/advisory/advisories.json` in the tool. `references/gnark-versions.md`
  carries the same JSON in a fenced block; a unit test fails if they differ.
- **Fallback loader.** If `go/packages` cannot type-check the target (missing
  dependencies, wrong toolchain), the tool falls back to `go/parser` and marks
  unresolved items (`resolved: false`). gnark ≥ v0.15 needs Go ≥ 1.25 and
  v0.16.4 needs Go 1.26, so type loading of a current gnark project needs a
  newer toolchain than the tool itself (`GOTOOLCHAIN=auto` handles this when
  the network allows it).
- **Offline by default.** The loader sets `GOPROXY=off` and strips `-mod=`
  from an inherited `GOFLAGS` before calling the go command, so loading a target
  never downloads modules and the target decides between its `vendor/` and the
  module cache. `--allow-network` is the explicit opt-in (PLAN §3 "never
  surprises the user").
- **Syntax-mode std shapes.** Without type information, a small table of gnark
  std struct shapes (`twistededwards.Point`, `eddsa.PublicKey/Signature`,
  `emulated.Element`, `sw_emulated.AffinePoint`, `ecdsa` types,
  `merkle.MerkleProof`, `uints.U8/U32/U64`) lets the walker lay out common
  witnesses. Other external types become `opaque` groups and make later
  offsets symbolic.
- **Witness-walk fidelity.** The walker reproduces `frontend/schema/walk.go`,
  including two behaviours that surprise users: tags on embedded fields are
  ignored, and nil pointers contribute no leaves. Expected layouts in the tests
  were produced by running gnark v0.14.0's own `schema.Walk` on the fixtures.
- **Hint reachability is a heuristic.** It is a per-function taint pass from
  `NewHint` results through assignments, range loops and API arithmetic to a
  list of constraining calls. "reached" means "flows into at least one
  constraint", never "bound". Outputs that leave the function (return, struct
  field, call to a non-API helper, composite literal) are `escapes`.
- **Fixtures.** `testdata/pool` and `testdata/edge` are separate modules that
  compile against gnark v0.14.0 (the newest release whose `go` directive works
  with Go 1.24). CI's offline step skips the typed-mode tests when the fixture
  dependencies are not cached; `make test-types` downloads them and requires
  typed mode.
- **`bundle` subcommand (M3 skeleton).** Context sharding is implemented in the
  Go tool rather than a separate `scripts/build-context`: circuit, integration,
  prover and all shards, with one circuit shard per package when there are more
  than two circuit packages. Bundles list source files with line counts and
  never inline source (PLAN §2 "Leave: full source duplicated in all bundles").
- **`assemble` subcommand (Phase 6).** Like `bundle`, the report assembler
  lives in the Go tool (`gnark-inventory assemble`, wrapped by
  `scripts/assemble`) rather than a separate Node script, so the plugin keeps
  one zero-dependency binary. Judgment prose the assembler cannot derive
  (posture, out-of-scope notes, companion availability, hardening notes) is
  carried in optional top-level `findings.json` fields, so the report is a
  pure function of validated inputs. It quotes constraint lines from the
  audited tree, refuses invalid input and forbidden clean claims, and counts
  coverage only from the ledger.
- **Docs lint.** `docs_test.go` fails when the skill, a command or an agent
  names a script, subcommand, flag, `validate` kind, reference file or
  `zk-audit:` agent that does not exist.
- **Not yet implemented.** The deep profile's "regenerate `Verifier.sol` and
  diff" is described in the I2 lens but not automated.

## Evals

- **Blind runs.** Fixtures keep their `// BUG:` comments for the inventory
  tests. `plugins/zk-audit/evals/sanitize` copies a fixture outside the
  repository, strips the hints with a per-fixture sed script and fails if
  hint text survives. Answer keys and eval PoCs live in `evals/<fixture>/`,
  which no skill file references; a docs test keeps fixture identifiers out
  of every plugin doc so hunters are not primed.
- **Answer keys score real impact, not the planted comment.** Several pool
  `BUG:` comments describe patterns that are harmless in context (one is a
  decoy), so the key records the reviewed ground truth and the accepted
  verdict range per item.
- **Eval PoCs** (`evals/pool/pocs`) run against gnark v0.14.0 in a sanitized
  scratch copy (`evals/run-pocs`, `make eval-pocs`, CI). They pin the
  templates in `poc-templates.md` to working code.

## Knowledge base

- **Source policy.** Every vector cites at least one of: a GHSA advisory, an
  audit report or the gnark PR that fixed an audit finding (taken from the
  "Client Response" links in `gnark/audits/2024-05 - zksecurity - gnark std.pdf`),
  a Least Authority report shipped in `gnark/audits/`, a `gnark/<path>`
  source reference at v0.16.4 that states the behaviour, a `gnark/CHANGELOG.md`
  entry, or the zkSecurity zk-skills entry a generic vector was ported from.
  `lint-kb` restricts URL hosts to an allow-list and, with `--gnark-src`,
  checks that every cited gnark path exists (it does, for v0.16.4).
- **Integration vectors without a ZK-specific source were left out.** Admin
  swap of a verifier or VK, nullifier check-then-store atomicity and reentrancy
  around verification are covered as checklist items in the I2 and I3 lens
  files instead of as catalog vectors, because no source in the allowed set
  documents them for gnark.
- **Vector count.** 79 vectors in 12 slices (PLAN target "about 80"). Slice and
  id scheme: V-H (hints), V-R (range), V-F (field), V-S (selector), V-M (hash /
  Merkle), V-E (curves / signatures), V-CM (commitments / recursion), V-PI
  (public inputs), V-VC (verifier contracts), V-PS (protocol state), V-PV
  (prover service), V-G (generic, ported from zkSecurity).
- **PoC templates were executed.** T-HINT-OVERRIDE, T-PROVE-VERIFY,
  T-ASSERT-OVERRIDE and T-ALIAS were run against gnark v0.14.0 on small
  circuits (a remainder hint without `r < b`, and `OmitModulusCheck`), and
  each demonstrated the bug with its honest control. `test.WithReplacementHint`
  exists only from v0.15 and is documented as such.

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
