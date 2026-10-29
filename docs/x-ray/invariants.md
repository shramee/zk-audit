# Invariant Map

> zk-audit's own rules: 29 runtime guards in the tool (G), 19 test-enforced sync and lint rules (T), 21 prompt-level rules (P). Refreshed 2026-10-29 for the tree after shramee/zk-audit#16; entries changed since the `4d9cf86` snapshot name the pull request that changed them.

Paths are relative to `plugins/zk-audit/skills/zk-audit/` unless they start
with `plugins/`, `docs/`, `test/`, `evals/` or `Makefile`; Go paths are
relative to `tools/gnark-inventory/`. Locations name files and functions, not
line numbers, which drift. **Enforced** says what actually stops a violation:
`Yes` (code refuses), `Partial` (code checks the shape, not the substance, or
only warns), `No` (an instruction to the model).

---

## 1. Runtime guards in the tool (G)

#### G-1
- **Rule:** every validator fails when it inspects zero items.
- **Where:** `internal/validate/validate.go` (empty ledger; empty findings need `no_findings: true` and a reason, then count as 1 item; stack and threat model count 1); `internal/kblint/kblint.go` (zero vectors); `main.go` (`bundle` with no bundle written); `docs_test.go` (`checked < 20`, `< 10` guards).
- **Tests:** `TestZeroItemsFail` (`internal/validate/validate_test.go`), `TestValidateExitCodes` (`main_test.go`).
- **Enforced:** Yes.

#### G-2
- **Rule:** a `confirmed` record carries `severity`, `confidence`, `evidence`, `proof`, `impact` and `gates`; a `lead` carries `code_smells` and `unverified`; `needs_validation` carries `blockers` and a `validation_plan`; `rejected` carries a `reason` and a `refuting_location`.
- **Where:** `schemas/findings.schema.json` (`oneOf` on `verdict`, `additionalProperties: false`).
- **Enforced:** Partial: `proof` is any non-empty string.

#### G-3
- **Rule:** `evidence: POC` requires `poc.result: demonstrated` and the PoC file; a model-circuit PoC (`demonstrated_on_model`) keeps `ANALYSIS`; a demonstrated PoC without `demonstrates` is a warning.
- **Where:** `internal/validate/validate.go` `checkPoC`, `PoCPath` (with `--out`: `poc.path` must be a regular file under `<out>/pocs/`); `assemble` writes `pocs/MANIFEST.json` with each file's hash.
- **Tests:** `TestPoCTruthfulness` (`internal/validate/validate_test.go`).
- **Enforced:** Yes for the label and the file (since shramee/zk-audit#11); Partial for the substance: nothing re-runs the PoC.

#### G-4
- **Rule:** a confirmed record with confidence ≥ 80 has a `fix`; confidence < 50 on a confirmed record is a warning.
- **Where:** `internal/validate/validate.go`.
- **Enforced:** Yes (error) / warning.

#### G-5
- **Rule:** fingerprints (`group_key`) are unique and shaped `a|b|bug-class`.
- **Where:** `internal/validate/validate.go`; `schemas/findings.schema.json`.
- **Enforced:** Yes for duplicates; whether two records *should* have merged is judgment (P-13).

#### G-6
- **Rule:** every `chain` entry names a fingerprint present in the file.
- **Where:** `internal/validate/validate.go`.
- **Enforced:** Yes.

#### G-7
- **Rule:** ledger unit ids are unique and read `<kind>:<subject>|<class>`.
- **Where:** `internal/validate/validate.go`; seeded that way by `internal/ledger/seed.go`.
- **Enforced:** Yes.

#### G-8
- **Rule:** `covered` units list `agent_ids` and `reviewed_paths`; with the output directory every agent of a covered or candidate unit has a saved output and the reviewed paths include the unit's own file; `blocked`, `deferred`, `not_applicable`, `out_of_scope` give a `reason`.
- **Where:** `internal/validate/validate.go` `semanticLedger` (`--out` checks); `ledger mark` runs them before writing; `critic-check` lists covered units with no saved output and inventory items no output names.
- **Tests:** `TestLedgerTruthfulness` (`internal/validate/validate_test.go`), `TestCheckAndVerify` (`internal/criticcheck`).
- **Enforced:** Yes for existence (since shramee/zk-audit#11); Partial for substance: an output that exists may still not discuss the unit (`critic-check` matching is lexical, shramee/zk-audit#16).

#### G-9
- **Rule:** `assemble` validates findings, ledger and stack first and writes no report on any error (exit 1).
- **Where:** `internal/assemble/assemble.go`, `main.go`.
- **Tests:** `TestRefusesInvalidInput` (`internal/assemble/assemble_test.go`), `TestAssembleCommand` (`main_test.go`).
- **Enforced:** Yes. `inventory.json` is decoded but not schema-validated (`assemble.go`).

#### G-10
- **Rule:** the report never makes a clean claim ("verified clean", "no bugs", "is secure", …).
- **Where:** `internal/assemble/assemble.go` `banned`, `checkClaims` (posture, no_findings_reason, out_of_scope, hardening, accepted risks and record text).
- **Enforced:** Partial: a fixed phrase list; other wording passes.

#### G-11
- **Rule:** coverage in `REPORT.md` comes only from the ledger: examined = `covered` only (a `candidate` is not examined); applicable = all minus `not_applicable` and `out_of_scope`.
- **Where:** `internal/assemble/assemble.go` `examined`.
- **Enforced:** Yes for the arithmetic (candidate excluded since shramee/zk-audit#11); the ledger is written through `ledger mark` (G-22).

#### G-12
- **Rule:** the same inputs render the same bytes; records sort by severity, confidence, title, fingerprint.
- **Where:** `internal/assemble/assemble.go`.
- **Tests:** `TestDeterministic` (`assemble_test.go`), `TestGoldenFull`, `TestGoldenEmpty`, `TestGoldenPartial`.
- **Enforced:** Yes.

#### G-13
- **Rule:** constraint quotes in the report are read from the audited tree, never from agent text; absolute paths, `..` and a symlink whose real path leaves the repository are refused.
- **Where:** `internal/assemble/render.go` `open` (`filepath.EvalSymlinks` on the root and the file, regular files only).
- **Tests:** `TestQuoteStaysInRepo`, `TestQuoteSymlinkEscape` (`internal/assemble/assemble_test.go`).
- **Enforced:** Yes (since shramee/zk-audit#11).

#### G-14
- **Rule:** loading the target never downloads modules unless `--allow-network`, and the target's environment cannot steer the go command.
- **Where:** `internal/load/load.go` `targetEnv` (drops `CGO_ENABLED`, `GOWORK`, `GOFLAGS`; sets `CGO_ENABLED=0`, `GOWORK=off`, empty `GOFLAGS`, and offline `GOPROXY=off`, `GOTOOLCHAIN=local`); `inventory` re-runs itself in the sandbox (no network, repository read-only).
- **Tests:** `TestTargetEnv` (`internal/load/load_test.go`), `TestInventoryInSandbox` (`cmd_test.go`).
- **Enforced:** Yes (since shramee/zk-audit#11); without an OS sandbox the environment rules still apply.

#### G-15
- **Rule:** the tool builds offline from vendored sources.
- **Where:** `scripts/gnark-inventory` (`GOWORK=off GOFLAGS=-mod=vendor`); CI step 1 runs with `GOPROXY=off` (`.github/workflows/ci.yml`).
- **Enforced:** Yes.

#### G-16
- **Rule:** the tool never writes into the audited repository, except the report copy of `assemble --file-output`.
- **Where:** `main.go` `refuseInRepo` (resolved paths, `fsutil.Inside`), called by `detect`, `inventory`, `bundle`, `assemble --out/--report`, `diff`, `convert`, `threat-model`, `verifier regen`; `harness` refuses a destination inside the repository; `args` refuses `--out` inside it.
- **Tests:** `TestRefuseWritesInRepo` (`cmd_test.go`), `TestRunLifecycleCommands` (`cmd_product_test.go`).
- **Enforced:** Yes: exit 2 before writing (since shramee/zk-audit#11).

#### G-17
- **Rule:** bundles list source files with line counts and never inline source.
- **Where:** `internal/bundle/bundle.go`, `render`.
- **Tests:** `TestBundles` (`internal/bundle/bundle_test.go`).
- **Enforced:** Yes.

#### G-18
- **Rule:** repository walks skip `.git`, `vendor`, `testdata`, `node_modules`, `.zk-audit` and every non-regular file (symlinks).
- **Where:** `internal/fsutil/walk.go`.
- **Enforced:** Yes for `fsutil.Walk`; `go/packages` loading follows the go command's own rules.

#### G-19
- **Rule:** the update check never blocks and warns only when the local version is lower.
- **Where:** `scripts/check-version` (always `exit 0`, 3 s limit, numeric compare).
- **Tests:** `TestCheckVersionScript` (`main_test.go`).
- **Enforced:** Yes.

#### G-20
- **Rule:** an eval copy is made outside the repository and contains no hint text.
- **Where:** `evals/sanitize` (refuses a destination inside the repo; fails if `BUG`, `OK:` or hint words survive).
- **Enforced:** Yes for the copy; see P-14 for installs.


#### G-21
- **Rule:** the invocation is parsed by code: unknown flags, two profiles, `--loop` outside 1–10, scope paths that do not exist or leave the repository, an `--out` inside it and a bad `--budget` are refused; run ids are `YYYYMMDD-HHMMSS`.
- **Where:** `internal/args/args.go` `Parse`, `resume`, `Save` (`<out>/run.json`).
- **Tests:** `internal/args/args_test.go`, `TestArgsCommand`, `TestRunLifecycleCommands`.
- **Enforced:** Yes (shramee/zk-audit#11; `--budget`, `--save` and resume in shramee/zk-audit#16), when the orchestrator calls `args`.

#### G-22
- **Rule:** the ledger and the agent index change only through the tool: `ledger mark` / `ledger add` validate the whole ledger (with the `--out` checks) before an atomic write; `agents save` keeps an index with status and attempts.
- **Where:** `cmd_ledger.go`, `internal/ledger/edit.go`, `internal/agents`.
- **Tests:** `TestLedgerAndAgentsCommands` (`cmd_test.go`).
- **Enforced:** Partial (shramee/zk-audit#11): the tool refuses bad edits; that the orchestrator uses it instead of Write is prompt-held.

#### G-23
- **Rule:** loop memory is held by the tool: NEW / KNOWN, "seen in k/N", rejected items kept, passes merged in order, none after a stop; the stop rule is no new fingerprint and no missing unit, or all planned passes.
- **Where:** `internal/memory/memory.go` `Merge`.
- **Tests:** `TestLoopPasses`, `TestStopRule`, `TestMergeRejectsInvalidFindings` (`internal/memory`).
- **Enforced:** Yes for tags and the stop rule (shramee/zk-audit#11); running a full pass is prompt-held.

#### G-24
- **Rule:** trusted-party records follow Gate 3: never a bare lead, at least medium for a power over soundness or funds (medium only with a mitigation), an accepted risk cites its `zk-audit.md` line, which must be an accepted risk or a party marked trusted in `threat-model.json`.
- **Where:** `internal/validate/validate.go` `checkTrust`, `checkThreatModel`.
- **Tests:** `TestTrustedPartyRules`, `TestAcceptedRiskAgainstThreatModel`.
- **Enforced:** Yes (shramee/zk-audit#13; the threat-model check in shramee/zk-audit#16).

#### G-25
- **Rule:** a record's severity-calibration anchor must exist and allow its verdict and severity.
- **Where:** `internal/validate/validate.go` `checkCalibration`, `internal/calibration`.
- **Tests:** `TestCalibrationAnchors`.
- **Enforced:** Yes for a named anchor; Partial: a confirmed record without an anchor is a warning (shramee/zk-audit#13).

#### G-26
- **Rule:** target code runs in an OS sandbox: own network namespace, read-only file system except the `--rw` directories, home directory masked, cgo off, a memory limit and a wall-clock kill (exit 124).
- **Where:** `internal/sandbox/sandbox.go` `Run`, `Stage2`; `scripts/sandbox`; `inventory` and `verifier regen` call it themselves.
- **Tests:** `TestNetworkDenied`, `TestWritesConfined`, `TestMemoryLimit`, `TestTimeout`, `TestGoCommandInside`, `TestForgeInside` (`internal/sandbox`; CI requires bubblewrap).
- **Enforced:** Yes on Linux with bubblewrap (shramee/zk-audit#11); macOS `sandbox-exec` is untested in CI and does not restrict reads; without either only the limits apply, with a warning.

#### G-27
- **Rule:** before each wave the run stops if estimated spend plus the wave's estimate crosses `--budget`; the stop is recorded, final unless the budget is raised on resume, and the report says it is partial.
- **Where:** `internal/budget/budget.go` `Check`, `ApplyBudget`; `internal/assemble` (partial notice, not-covered line).
- **Tests:** `TestCheckStopsBeforeTheCeiling`, `TestRaisedBudgetLiftsTheStop`, `TestGoldenPartial`.
- **Enforced:** Partial (shramee/zk-audit#16): the decision is code; calling `budget check` before each wave is prompt-held, and spend is an estimate from reported tokens.

#### G-28
- **Rule:** every missing unit the tool computes needs a decision in the ledger (run in a wave, deferred or blocked with a reason, or dismissed with a note) before the report.
- **Where:** `internal/criticcheck` `Check`, `Undecided`; `critic-check --verify` exit 1.
- **Tests:** `TestCheckAndVerify`.
- **Enforced:** Partial (shramee/zk-audit#16): `--verify` is called by instruction.

#### G-29
- **Rule:** `zk-audit.md` is parsed by code: unknown trust levels, duplicate ids, accepted risks from untrusted parties, prior findings without a group_key fingerprint and scope paths leaving the repository are refused; every entry keeps its line.
- **Where:** `internal/threatmodel`; `schemas/threat-model.schema.json`.
- **Tests:** `internal/threatmodel/threatmodel_test.go` (the shipped template parses with no entries).
- **Enforced:** Yes for the file (shramee/zk-audit#16); its use in judging is prompt-held apart from G-24.

---

## 2. Test-enforced sync and lint rules (T)

#### T-1
- **Rule:** the schemas embedded in the tool equal `schemas/*.json`.
- **Where:** `TestSchemasInSync` (`internal/validate/validate_test.go`); `make sync-schemas`.

#### T-2
- **Rule:** the JSON block in `references/gnark-versions.md` equals the embedded `internal/advisory/advisories.json`, and every advisory has a human-readable row.
- **Where:** `internal/kblint/kblint.go`; `TestVersionsInSync` (`kblint_test.go`).

#### T-3
- **Rule:** `plugins/zk-audit/agents/*.md` equal `agents/*.md` in the skill folder.
- **Where:** `TestAgentBriefsInSync` (`docs_test.go`); `make sync-agents`.

#### T-4
- **Rule:** marketplace entry, `plugin.json`, the tool's `Version` and `VERSION` agree.
- **Where:** `TestPluginMetadata` (`main_test.go`).

#### T-5
- **Rule:** every script, subcommand, flag, `validate` kind, `references/*.md` file and `zk-audit:<id>` named in the skill, commands, agents or plugin README exists.
- **Where:** `TestDocumentedCommandsExist` (`docs_test.go`), self-test `TestDocsLintCatchesMistakes`.

#### T-6
- **Rule:** the skill folder is self-contained: no `{plugin}`, no `{skill}/..`, every `{skill}/<path>` exists; a copy alone runs build → detect → inventory → validate → bundle → assemble → lint-kb.
- **Where:** `TestSkillIsSelfContained` (`docs_test.go`); `test/standalone-skill.sh` (`make check`).

#### T-7
- **Rule:** every `${CLAUDE_PLUGIN_ROOT}/<path>` in a command exists.
- **Where:** `TestCommandPathsExist` (`docs_test.go`).

#### T-8
- **Rule:** no skill, command or agent doc names an eval-fixture identifier.
- **Where:** `TestDocsDoNotNameEvalFixtures` (`docs_test.go`).

#### T-9
- **Rule:** every vector has `D`, `FP`, `Source` (allowed host or `gnark/<path>`), `Seed` (a real `FG-*` rule or pattern) and `PoC` (a real template); ids unique; slice counts match `index.md`.
- **Where:** `internal/kblint/kblint.go` (hosts); `TestKnowledgeBase`, `TestLintCatchesProblems` (`kblint_test.go`); `make lint-kb`.

#### T-10
- **Rule:** `SKILL.md` stays under 500 lines with frontmatter; every `references/…` it names exists, at most one level below `references/`.
- **Where:** `internal/kblint/kblint.go`.

#### T-11
- **Rule:** footgun rule ids are unique.
- **Where:** `TestRulesUnique` (`internal/inventory/inventory_test.go`).

#### T-12
- **Rule:** public-witness order matches gnark v0.14.0's `schema.Walk` on the fixtures.
- **Where:** `TestPoolWitnessOrder`, `TestEdgeLayout` (`inventory_test.go`); skipped offline, required by `make test-types` in CI.

#### T-13
- **Rule:** the eval PoCs demonstrate the planted bugs (and the decoys stay rejected) on sanitized copies: pool and lib-gadgets in Go (the latter on generated harness wrappers), liveness-roots and sol-gnark-abi in Foundry (the latter against a real gnark-exported verifier).
- **Where:** `evals/run-pocs`, `make eval-pocs` (CI job `check`).


#### T-14
- **Rule:** the profile and agent tables in `SKILL.md` and `references/orchestration.md` are generated from `profiles.json`; every lens file is used and exists.
- **Where:** `TestGeneratedDocsInSync`, `TestEveryLensFileIsUsed` (`internal/profile`); `make sync-profiles`.

#### T-15
- **Rule:** neither install carries `evals/` or `testdata/`.
- **Where:** `TestInstallShipsNoFixtures` (`docs_test.go`).

#### T-16
- **Rule:** the read-only agent types declare a `tools:` list without write-capable tools; every agent declares tools.
- **Where:** `TestReadOnlyAgentsHaveNoWriteTools`, `TestEveryAgentDeclaresTools` (`docs_test.go`).

#### T-17
- **Rule:** the cost model gives back every measured calibration run within its stated spread.
- **Where:** `TestModelReproducesMeasuredRuns` (`internal/estimate`).

#### T-18
- **Rule:** the PoC templates, the harness, a Foundry test against the exported verifier and the inventory work on gnark v0.10.0, v0.14.0 and v0.16.4.
- **Where:** `test/versions/run --foundry --check` (CI job `versions`).

#### T-19
- **Rule:** every Go file is gofmt-clean; tool and scorer coverage stays at or above 65 %; the plugin and the marketplace pass `claude plugin validate`; VERSION, `plugin.json`, the marketplace entry and the tool `Version` agree and `CHANGELOG.md` has an Unreleased section (a release tag also needs its section).
- **Where:** `make fmt-check`, `make cover`, `make validate-plugin`, `make release-check` (CI jobs `check`, `plugin`; `release.yml`).

---

## 3. Prompt-only rules (P)

#### P-1
- **Rule:** agents never create, edit or delete files in the target.
- **Where:** `SKILL.md` §3 rule 1; `references/shared-rules.md` §1; `agents/hunter.md`, `agents/critic.md`, `agents/refuter.md`.
- **Enforced:** Yes in a plugin install for hunters, critics and the refuter (`zk-audit:hunter`, `zk-audit:critic`, `zk-audit:refuter`: `tools: Read, Grep, Glob`, T-16; since shramee/zk-audit#11). No in a standalone install (general-purpose agents limited by prompt) and for the poc-builder, which keeps `Write Edit Bash` and works in the worktree.

#### P-2
- **Rule:** an agent's FINDING block has a concrete `proof:`; otherwise it is a LEAD.
- **Where:** `references/shared-rules.md`.
- **Enforced:** No at the agent level; G-2 checks only that a confirmed record's `proof` is non-empty.

#### P-3
- **Rule:** PoCs run only in `<out>/worktree`, through the sandbox, offline.
- **Where:** `SKILL.md` §3 rule 3; `agents/poc-builder.md`; `references/orchestration.md` Turn 6 (the exact `scripts/sandbox` command).
- **Enforced:** Partial (since shramee/zk-audit#11): the sandbox (G-26) confines what runs inside it; that the poc-builder runs every test through it is an instruction, since it keeps Bash.

#### P-4
- **Rule:** `demonstrated` means the attack passes, the honest control fails and the sanity case passes.
- **Where:** `agents/poc-builder.md`.
- **Enforced:** No (G-3 checks the label only).

#### P-5
- **Rule:** at most six agents run at once.
- **Where:** `references/orchestration.md`, `SKILL.md` Phase 2.
- **Enforced:** No.

#### P-6
- **Rule:** nothing is installed without an explicit yes.
- **Where:** `SKILL.md` §3 rule 4; `references/modes/setup.md` step 7.
- **Enforced:** No; `/zk-audit:setup` allows `Bash`. The session's permission prompts are the guard.

#### P-7
- **Rule:** no network during an audit beyond the update check and consented downloads.
- **Where:** `SKILL.md` §3 rule 8.
- **Enforced:** Partial: the tool's go invocations (G-14) and everything in the sandbox (G-26) are offline; read-only agent types have no network tool; the orchestrator and the poc-builder are limited by the session's permissions.

#### P-8
- **Rule:** `binding-table.md` holds facts and source expressions only, unknown cells `?`, no verdicts (it is inlined into every bundle).
- **Where:** `SKILL.md` Phase 1 step 2.
- **Enforced:** No.

#### P-9
- **Rule:** the refuter did not see the hunt and starts from `refuted: true`.
- **Where:** `references/judging.md` §6; `agents/refuter.md`.
- **Enforced:** Partial: a new agent has a fresh context; the prompt content is up to the orchestrator.

#### P-10
- **Rule:** one question (profile, model) before the first spawn, asked after the inventory with each profile's cost range from `estimate`; nothing else before recon finishes.
- **Where:** `SKILL.md` §2; `references/orchestration.md` Turn 2.
- **Enforced:** No; the estimate itself is code (shramee/zk-audit#16).

#### P-11
- **Rule:** `REPORT.md` is never edited by hand.
- **Where:** `SKILL.md` Phase 6 step 4; `references/report-format.md`.
- **Enforced:** No (a rerun of `assemble` overwrites it).

#### P-12
- **Rule:** every unit still `planned` or `in_progress` is closed as `deferred` or `blocked` with a reason before the report, and every missing unit has a decision.
- **Where:** `SKILL.md` Phase 6 step 2; `orchestration.md` Turns 7–8; `ledger mark --from planned`.
- **Enforced:** Partial: `assemble` warns per open unit and lists it as not examined; `critic-check --verify` fails while a missing unit has no decision (G-28).

#### P-13
- **Rule:** dedup never merges across circuits or functions and keeps distinct fixes as options.
- **Where:** `references/judging.md` §1.
- **Enforced:** No (G-5 only rejects exact duplicates).

#### P-14
- **Rule:** answer keys and planted-bug hints never reach an audit's inputs.
- **Where:** `evals/` and `testdata/` at the repository root (shramee/zk-audit#8); T-8, T-15, G-20; `evals/run-audit` denies reads of `evals/`, `testdata/`, `docs/`, `test/` and `PLAN.md`.
- **Enforced:** Yes for installs (neither carries them); Partial for a session run from a checkout, where the deny rules of the runner apply.

#### P-15
- **Rule:** `run-id` is `YYYYMMDD-HHMMSS`.
- **Where:** `SKILL.md` §3 rule 2; `args` (G-21).
- **Enforced:** Yes when the run starts with `args` (since shramee/zk-audit#11); `findings.json` `run_id` is checked by the schema.

#### P-16
- **Rule:** an inventory hint status "reached" means "flows into at least one constraint", never "bound".
- **Where:** `docs/design-notes.md` "Hint reachability is a heuristic"; `internal/inventory/hints.go`.
- **Enforced:** No (interpretation by lenses).

#### P-17
- **Rule:** the profile → agent sets agree everywhere they are listed.
- **Where:** `internal/profile/profiles.json` is the one source; `bundle`, the ledger seeder, `args`, `estimate` and the generated doc tables read it.
- **Enforced:** Yes (T-14; since shramee/zk-audit#11).

#### P-18
- **Rule:** loop mode tags records `NEW` / `KNOWN` and stops when a pass adds nothing new and the critic reports nothing missing.
- **Where:** `references/orchestration.md` "Loop mode"; `gnark-inventory memory` (G-23).
- **Enforced:** Yes for tags and the stop rule (since shramee/zk-audit#11); running each pass in full is prompt-held, and no measured run has exercised it since.

#### P-19
- **Rule:** an agent that is stopped, refused or fails is retried once in plain words, then recorded as blocked with its units; a model fallback the runtime reports is recorded.
- **Where:** `references/orchestration.md` "Recovery rule"; `agents save --status ... --model` (attempts counted), `status` lists agents to retry and blocked ones, `assemble` lists them under Not covered.
- **Enforced:** Partial (shramee/zk-audit#16): the records are code; retrying and recording are instructions.

#### P-20
- **Rule:** spend is recorded per agent with the usage the runtime shows, and never guessed.
- **Where:** `references/orchestration.md` Turn 4 step 1 and "Budget"; `agents save --tokens`, `budget record`.
- **Enforced:** No for the recording; an agent recorded without tokens counts at its role's calibrated average and is marked `estimated` (shramee/zk-audit#16).

#### P-21
- **Rule:** a resumed run never respawns an agent whose output is saved.
- **Where:** `references/modes/resume.md`; `gnark-inventory status` lists saved, missing, retry and blocked agents.
- **Enforced:** Partial (shramee/zk-audit#16): the state is computed; respawning is the orchestrator's choice.
