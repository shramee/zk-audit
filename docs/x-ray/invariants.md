# Invariant Map

> zk-audit's own rules: 20 runtime guards in the tool (G), 13 test-enforced sync and lint rules (T), 18 prompt-only rules (P)

Paths are relative to `plugins/zk-audit/skills/zk-audit/` unless they start
with `plugins/`, `docs/`, `test/` or `Makefile`; Go paths are relative to
`tools/gnark-inventory/`. **Enforced** says what actually stops a violation:
`Yes` (code refuses), `Partial` (code checks the shape, not the substance, or
only warns), `No` (an instruction to the model).

---

## 1. Runtime guards in the tool (G)

#### G-1
- **Rule:** every validator fails when it inspects zero items.
- **Where:** `internal/validate/validate.go:180-182` (empty ledger), `:109-114` (empty findings need `no_findings: true` and a reason, then count as 1 item), `:69-70` (stack counts 1); `internal/kblint/kblint.go:103-105` (zero vectors); `main.go:286-288` (`bundle` with no bundle written); `docs_test.go` (`checked < 20`, `< 10` guards).
- **Tests:** `TestZeroItemsFail` (`internal/validate/validate_test.go:126`), `TestValidateExitCodes` (`main_test.go:152`).
- **Enforced:** Yes.

#### G-2
- **Rule:** a `confirmed` record carries `severity`, `confidence`, `evidence`, `proof`, `impact` and `gates`; a `lead` carries `code_smells` and `unverified`; `needs_validation` carries `blockers` and a `validation_plan`; `rejected` carries a `reason` and a `refuting_location`.
- **Where:** `schemas/findings.schema.json:132-196` (`oneOf` on `verdict`, `additionalProperties: false`).
- **Enforced:** Partial: `proof` is any non-empty string.

#### G-3
- **Rule:** `evidence: POC` requires `poc.result: demonstrated`; a demonstrated PoC labelled `ANALYSIS` is a warning.
- **Where:** `internal/validate/validate.go:136-143`.
- **Enforced:** Partial: the result is reported by the poc-builder; nothing re-runs the PoC or checks that `poc.path` exists.

#### G-4
- **Rule:** a confirmed record with confidence ≥ 80 has a `fix`; confidence < 50 on a confirmed record is a warning.
- **Where:** `internal/validate/validate.go:144-149`.
- **Enforced:** Yes (error) / warning.

#### G-5
- **Rule:** fingerprints (`group_key`) are unique and shaped `a|b|bug-class`.
- **Where:** `internal/validate/validate.go:128-130`; `schemas/findings.schema.json:45`.
- **Enforced:** Yes for duplicates; whether two records *should* have merged is judgment (P-13).

#### G-6
- **Rule:** every `chain` entry names a fingerprint present in the file.
- **Where:** `internal/validate/validate.go:150-154`.
- **Enforced:** Yes.

#### G-7
- **Rule:** ledger unit ids are unique and read `<kind>:<subject>|<class>`.
- **Where:** `internal/validate/validate.go:186-197`; seeded that way by `internal/ledger/seed.go:63-80`.
- **Enforced:** Yes.

#### G-8
- **Rule:** `covered` units list `agent_ids` and `reviewed_paths`; `candidate` units list `result_fingerprints` and `agent_ids`; `blocked`, `deferred`, `not_applicable`, `out_of_scope` give a `reason`.
- **Where:** `internal/validate/validate.go:199-215`.
- **Enforced:** Partial: non-empty lists only. No check that an `agent_ids` entry is a real lens, that `<out>/agents/<ID>.md` exists, or that `reviewed_paths` exist or belong to the unit.

#### G-9
- **Rule:** `assemble` validates findings, ledger and stack first and writes no report on any error (exit 1).
- **Where:** `internal/assemble/assemble.go:89-100`, `main.go:357-366`.
- **Tests:** `TestRefusesInvalidInput` (`internal/assemble/assemble_test.go:157`), `TestAssembleCommand` (`main_test.go`).
- **Enforced:** Yes. `inventory.json` is decoded but not schema-validated (`assemble.go:114-123`).

#### G-10
- **Rule:** the report never makes a clean claim ("verified clean", "no bugs", "is secure", …).
- **Where:** `internal/assemble/assemble.go:58-61` (regex), `:146-165` (checked in posture, no_findings_reason, out_of_scope, hardening and record text).
- **Enforced:** Partial: a fixed phrase list; other wording passes.

#### G-11
- **Rule:** coverage in `REPORT.md` comes only from the ledger: examined = `covered` + `candidate`; applicable = all minus `not_applicable` and `out_of_scope`.
- **Where:** `internal/assemble/assemble.go:259-274`, `internal/assemble/render.go:526`.
- **Enforced:** Yes for the arithmetic; the ledger itself is written by the model (G-8, P-12).

#### G-12
- **Rule:** the same inputs render the same bytes; records sort by severity, confidence, title, fingerprint.
- **Where:** `internal/assemble/assemble.go:225-241`.
- **Tests:** `TestDeterministic` (`assemble_test.go:122`), `TestGoldenFull` (`:51`), `TestGoldenEmpty` (`:97`).
- **Enforced:** Yes.

#### G-13
- **Rule:** constraint quotes in the report are read from the audited tree, never from agent text; absolute paths and paths starting with `..` are refused.
- **Where:** `internal/assemble/render.go:453-457`.
- **Tests:** `TestQuoteStaysInRepo` (`assemble_test.go:205`).
- **Enforced:** Partial: `os.Open` follows a symlink inside the repository that points outside it.

#### G-14
- **Rule:** loading the target never downloads modules unless `--allow-network`; an inherited `-mod=` flag is dropped so the target picks vendor or module cache.
- **Where:** `internal/load/load.go:251-270`.
- **Tests:** `TestTargetEnv` (`internal/load/load_test.go:10`).
- **Enforced:** Yes for module downloads. The rest of the caller's environment passes through (`CGO_ENABLED`, `GOFLAGS` other than `-mod`, `GOWORK`).

#### G-15
- **Rule:** the tool builds offline from vendored sources.
- **Where:** `scripts/gnark-inventory:21` (`GOWORK=off GOFLAGS=-mod=vendor`); CI step 1 runs with `GOPROXY=off` (`.github/workflows/ci.yml`).
- **Enforced:** Yes.

#### G-16
- **Rule:** the tool does not write into the audited repository by accident.
- **Where:** `main.go:176-178` (`inventory --out` inside the repo), `main.go:371-373` (`assemble --report` inside the repo).
- **Enforced:** Partial: both only warn on stderr and then write.

#### G-17
- **Rule:** bundles list source files with line counts and never inline source.
- **Where:** `internal/bundle/bundle.go:1-4`, `render` (`:321`).
- **Tests:** `TestBundles` (`internal/bundle/bundle_test.go:59`).
- **Enforced:** Yes.

#### G-18
- **Rule:** repository walks skip `.git`, `vendor`, `testdata`, `node_modules`, `.zk-audit` and every non-regular file (symlinks).
- **Where:** `internal/fsutil/walk.go:18-21`, `:47-49`.
- **Enforced:** Yes for `fsutil.Walk`; `go/packages` loading follows the go command's own rules.

#### G-19
- **Rule:** the update check never blocks and warns only when the local version is lower.
- **Where:** `scripts/check-version` (always `exit 0`, 3 s limit, numeric compare).
- **Tests:** `TestCheckVersionScript` (`main_test.go:64`).
- **Enforced:** Yes.

#### G-20
- **Rule:** an eval copy is made outside the repository and contains no hint text.
- **Where:** `plugins/zk-audit/evals/sanitize:25-27` (refuses a destination inside the repo), `:32-36` (fails if `BUG`, `OK:` or hint words survive).
- **Enforced:** Yes for the copy; see P-14 for what else ships.

---

## 2. Test-enforced sync and lint rules (T)

#### T-1
- **Rule:** the schemas embedded in the tool equal `schemas/*.json`.
- **Where:** `TestSchemasInSync` (`internal/validate/validate_test.go:13`); `make sync-schemas`.

#### T-2
- **Rule:** the JSON block in `references/gnark-versions.md` equals the embedded `internal/advisory/advisories.json`, and every advisory has a human-readable row.
- **Where:** `internal/kblint/kblint.go:318-349`; `TestVersionsInSync` (`kblint_test.go:32`).

#### T-3
- **Rule:** `plugins/zk-audit/agents/*.md` equal `agents/*.md` in the skill folder.
- **Where:** `TestAgentBriefsInSync` (`docs_test.go:268`); `make sync-agents`.

#### T-4
- **Rule:** marketplace entry, `plugin.json`, the tool's `Version` and `VERSION` agree.
- **Where:** `TestPluginMetadata` (`main_test.go:20`).

#### T-5
- **Rule:** every script, subcommand, flag, `validate` kind, `references/*.md` file and `zk-audit:<id>` named in the skill, commands, agents or plugin README exists.
- **Where:** `TestDocumentedCommandsExist` (`docs_test.go:63`), self-test `TestDocsLintCatchesMistakes` (`:146`).

#### T-6
- **Rule:** the skill folder is self-contained: no `{plugin}`, no `{skill}/..`, every `{skill}/<path>` exists; a copy alone runs build → detect → inventory → validate → bundle → assemble → lint-kb.
- **Where:** `TestSkillIsSelfContained` (`docs_test.go:208`); `test/standalone-skill.sh` (`make check`).

#### T-7
- **Rule:** every `${CLAUDE_PLUGIN_ROOT}/<path>` in a command exists.
- **Where:** `TestCommandPathsExist` (`docs_test.go:240`).

#### T-8
- **Rule:** no skill, command or agent doc names an eval-fixture identifier.
- **Where:** `TestDocsDoNotNameEvalFixtures` (`docs_test.go:135`).

#### T-9
- **Rule:** every vector has `D`, `FP`, `Source` (allowed host or `gnark/<path>`), `Seed` (a real `FG-*` rule or pattern) and `PoC` (a real template); ids unique; slice counts match `index.md`.
- **Where:** `internal/kblint/kblint.go:134-317` (hosts `:54`); `TestKnowledgeBase`, `TestLintCatchesProblems` (`kblint_test.go:17`, `:76`); `make lint-kb`.

#### T-10
- **Rule:** `SKILL.md` stays under 500 lines with frontmatter; every `references/…` it names exists, at most one level below `references/`.
- **Where:** `internal/kblint/kblint.go:351-385`.

#### T-11
- **Rule:** footgun rule ids are unique.
- **Where:** `TestRulesUnique` (`internal/inventory/inventory_test.go:262`).

#### T-12
- **Rule:** public-witness order matches gnark v0.14.0's `schema.Walk` on the fixtures.
- **Where:** `TestPoolWitnessOrder`, `TestEdgeLayout` (`inventory_test.go:73`, `:208`); skipped offline, required by `make test-types` in CI.

#### T-13
- **Rule:** the eval PoCs demonstrate the planted bugs (and the decoy stays rejected) on a sanitized copy.
- **Where:** `plugins/zk-audit/evals/run-pocs`, `make eval-pocs` (CI step 3).

---

## 3. Prompt-only rules (P)

#### P-1
- **Rule:** agents never create, edit or delete files in the target.
- **Where:** `SKILL.md` §3 rule 1; `references/shared-rules.md` §1; hunting prompt in `references/orchestration.md` Turn 4.
- **Enforced:** No for hunters and the critic (general-purpose agents with the session's tools). Yes only for `zk-audit:refuter` in a plugin install (`tools: Read, Grep, Glob`, `agents/refuter.md:4-7`); in a standalone install the refuter is general-purpose too.

#### P-2
- **Rule:** an agent's FINDING block has a concrete `proof:`; otherwise it is a LEAD.
- **Where:** `references/shared-rules.md:92-94`.
- **Enforced:** No at the agent level; G-2 checks only that a confirmed record's `proof` is non-empty.

#### P-3
- **Rule:** PoCs run only in `<out>/worktree`, with `timeout 600` and no network.
- **Where:** `SKILL.md` §3 rule 3; `agents/poc-builder.md` Rules.
- **Enforced:** No. `GOPROXY=off` stops module downloads only; the target's package `init` functions and any `TestMain` in the PoC's package run with the user's privileges.

#### P-4
- **Rule:** `demonstrated` means the attack passes, the honest control fails and the sanity case passes.
- **Where:** `agents/poc-builder.md:59-60`.
- **Enforced:** No (G-3 checks the label only).

#### P-5
- **Rule:** at most six agents run at once.
- **Where:** `references/orchestration.md:111`, `SKILL.md` Phase 2.
- **Enforced:** No.

#### P-6
- **Rule:** nothing is installed without an explicit yes.
- **Where:** `SKILL.md` §3 rule 4; `references/modes/setup.md` step 7.
- **Enforced:** No; `/zk-audit:setup` allows `Bash`. The session's permission prompts are the guard.

#### P-7
- **Rule:** no network during an audit beyond the update check and consented downloads.
- **Where:** `SKILL.md` §3 rule 8.
- **Enforced:** Partial: G-14 and G-15 cover the tool's go invocations; agents are not restricted.

#### P-8
- **Rule:** `binding-table.md` holds facts and source expressions only, unknown cells `?`, no verdicts (it is inlined into every bundle).
- **Where:** `SKILL.md` Phase 1 step 2.
- **Enforced:** No.

#### P-9
- **Rule:** the refuter did not see the hunt and starts from `refuted: true`.
- **Where:** `references/judging.md` §6; `agents/refuter.md`.
- **Enforced:** Partial: a new agent has a fresh context; the prompt content is up to the orchestrator.

#### P-10
- **Rule:** one question (profile, model) before the first spawn; nothing else before recon finishes.
- **Where:** `SKILL.md` §2.
- **Enforced:** No.

#### P-11
- **Rule:** `REPORT.md` is never edited by hand.
- **Where:** `SKILL.md` Phase 6 step 4; `references/report-format.md:5`.
- **Enforced:** No (a rerun of `assemble` overwrites it).

#### P-12
- **Rule:** every unit still `planned` or `in_progress` is closed as `deferred` or `blocked` with a reason before the report.
- **Where:** `SKILL.md` Phase 6 step 2; `orchestration.md` Turn 8.
- **Enforced:** Partial: `assemble` warns per open unit (`assemble.go:209-211`) and still renders; the report lists them as not examined.

#### P-13
- **Rule:** dedup never merges across circuits or functions and keeps distinct fixes as options.
- **Where:** `references/judging.md` §1.
- **Enforced:** No (G-5 only rejects exact duplicates).

#### P-14
- **Rule:** answer keys and planted-bug hints never reach an audit's inputs.
- **Where:** T-8, G-20; the baseline run's orchestrator was told not to read `testdata/`, tests, `evals/`, `docs/` or `PLAN.md` (`plugins/zk-audit/evals/baseline/pool-quick.md`).
- **Enforced:** Partial: a plugin install copies `evals/` (answer keys) and the tool's `testdata/` (fixtures with `BUG:` comments) into the plugin cache, and the skill folder carries `testdata/`; only instructions keep hunters away from them.

#### P-15
- **Rule:** `run-id` is `YYYYMMDD-HHMMSS`.
- **Where:** `SKILL.md` §3 rule 2.
- **Enforced:** Partial: `findings.json` `run_id` must match (`schemas/findings.schema.json:13`); the output directory name is not checked (a live recon run named it `recon-run`, `docs/pashov-parity.md`).

#### P-16
- **Rule:** an inventory hint status "reached" means "flows into at least one constraint", never "bound".
- **Where:** `docs/design-notes.md` "Hint reachability is a heuristic"; `internal/inventory/hints.go:168`.
- **Enforced:** No (interpretation by lenses).

#### P-17
- **Rule:** the profile → agent sets agree in `SKILL.md` §2, `references/orchestration.md`, `README.md` and `bundle.Agents`.
- **Where:** `internal/bundle/bundle.go:39-68` is the only executable copy.
- **Enforced:** No test compares them (they agree today).

#### P-18
- **Rule:** loop mode tags records `NEW` / `KNOWN` from `<out>/memory.json` and stops when a pass adds nothing.
- **Where:** `references/orchestration.md` "Loop mode"; `run_tag` enum in the schema.
- **Enforced:** No tool support.
