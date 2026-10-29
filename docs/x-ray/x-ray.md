# X-Ray Report

> zk-audit | 21,158 Go lines (tool, non-blank non-comment, non-test; 24,054 raw) + 6,362 lines of prompts and knowledge base | `dc25a00` (`feat/product-ops`: `main` at `691d227` + shramee/zk-audit#16) | Claude Code plugin + standalone skill, Go 1.24 | 29/10/26

This is an x-ray of zk-audit itself, in the format of
[pashov/skills `x-ray`](https://github.com/pashov/skills/tree/main/x-ray),
adapted from a Solidity protocol to an agent-plus-tool project: "contracts"
are components, "entry points" are commands, skill modes and CLI subcommands,
and "invariants" are the system's own rules and where (or whether) code
enforces them. Companion files: [entry-points.md](entry-points.md),
[calls.md](calls.md), [invariants.md](invariants.md),
[architecture.svg](architecture.svg) (source: `architecture.json`,
`gen_architecture.py`).

It refreshes the snapshot of `4d9cf86` (28/10/26) after the follow-up list
(shramee/zk-audit#8 to #16); that snapshot is in git history. Items it
raised are marked with the pull request that resolved them.

`{skill}` = `plugins/zk-audit/skills/zk-audit/`; `<out>` = `~/.zk-audit/<repo>/<run-id>/`.

---

## 1. Overview

**What it does:** a Claude Code skill that audits gnark (Go) ZK circuits and
the Solidity verifier, protocol state and prover service that consume their
proofs, by running a deterministic Go tool (inventory, cost estimate,
bundles, ledger, budget, critic check, validation, report), fanning bounded
read-only hunting agents over per-agent bundles, judging, proving with Go /
Foundry PoCs inside an OS sandbox, and rendering a report from
schema-validated JSON.

- **Users:** circuit authors and auditors running Claude Code on a gnark repository or a gnark gadget library.
- **Core flow:** `/zk-audit` → Detect → Recon (+ threat model, estimate) → Hunt → Judge → Prove → Critique → Report; `/zk-audit resume` continues an interrupted run.
- **Key mechanism:** judgment by the model, bookkeeping by code: the tool parses the invocation and the threat model, writes the inventory, the ledger seed, the estimate and the bundles, records agents, spend and ledger changes, computes the missing units, validates every JSON hand-off, and renders `REPORT.md`.
- **Install model:** a Claude Code plugin (marketplace `zk-audit`) or the skill folder copied alone into `~/.claude/skills/zk-audit` ([pashov-parity.md](../pashov-parity.md)).
- **Control model:** the user's session permissions, plus read-only plugin agent types and an OS sandbox for target code; no server, no account, no secret. One outbound request by default (update check).

![architecture](architecture.svg)

### Components in scope

| Subsystem | Key files | Size | Role |
|---|---|---:|---|
| Skill entry | `{skill}/SKILL.md`, `references/orchestration.md`, `references/modes/*.md` (setup, recon, diff, library, resume) | 446 + 463 + 251 lines | Mode selection, hard rules, phases, turns, budget, resume, loop mode |
| Knowledge base | `references/agents/` (20 lens files), `references/attack-vectors/` (16 slices, 111 vectors), `judging.md`, `severity-calibration.md` (21 anchors), `shared-rules.md`, `senior-auditor-sop.md`, `poc-templates.md`, `gnark-versions.md`, `gnark-api-footguns.md`, `rationalizations.md`, `report-format.md`, `companions.md` | 6,362 lines (62 files with the skill, orchestration, modes, agent briefs and commands) | What agents read; inlined into bundles by the tool |
| Profiles | `tools/gnark-inventory/internal/profile/profiles.json` | 35 lenses, 2 critics, 4 profiles | One source for bundles, ledger seeding, `args`, `estimate` and the generated doc tables |
| Agent briefs | `{skill}/agents/{hunter,critic,poc-builder,refuter}.md` (canonical), `plugins/zk-audit/agents/` (plugin copies) | 255 lines | Read-only hunter and critic types; PoC writer/runner; fresh-context refuter |
| Plugin shell | `.claude-plugin/marketplace.json`, `plugins/zk-audit/.claude-plugin/plugin.json`, `plugins/zk-audit/commands/*.md` | 4 commands | Marketplace, manifest, thin commands (setup, recon, diff, resume) |
| Inventory tool | `{skill}/tools/gnark-inventory` (34 packages, vendored `x/tools`, `x/mod`, `x/sync`) | 21,158 Go lines | 25 subcommands ([entry-points.md](entry-points.md)) |
| Templates | `{skill}/templates/zk-audit.md` | 1 | Threat-model file the repository keeps |
| Wrappers | `{skill}/scripts/{gnark-inventory,sandbox,validate-findings,validate-ledger,assemble,check-version}` | 6 scripts | Build-once wrapper (source hash), sandbox, aliases, update check |
| Schemas | `{skill}/schemas/{findings,ledger,stack,threat-model}.schema.json` (+ embedded copies) | 4 | Contracts between phases |
| Evals | `evals/` (top level: 9 cases, 4 fixture keys, scorer with `pilot`, `run-audit`, `run-pocs`, sanitizer, baselines, `pilots/`), `testdata/` (11 fixtures and goldens) | — | Blind-run scoring, executed PoCs, pilot protocol tooling; not installed |
| Dev / CI | `Makefile`, `.github/workflows/{ci,release}.yml`, `scripts/release-{check,notes}`, `test/standalone-skill.sh`, `test/versions/run`, `test/parity/` | 3 CI jobs + matrix, 1 release workflow | gofmt, offline checks, typed fixtures, coverage, eval PoCs, plugin validate, version matrix, releases |

### How it fits together

The core trick: every hand-off between model steps is a file the tool can
check (`run.json`, `stack.json`, `threat-model.json`, `inventory.json`,
`coverage-ledger.json`, `agents/index.json`, `spend.json`,
`critic-check.json`, `findings.json`), and the only artifact a reader sees
(`REPORT.md`) is rendered by code from those files.

#### Full audit

```text
/zk-audit [profile] [flags]                            SKILL.md §1-§4
├─ args --save → <out>/run.json                        (flags, scope, budget; resume reads it back)
├─ P0 detect → stack.json · preflight · sandbox --check   (+ check-version, companion detection)
├─ P1 threat-model → threat-model.json (zk-audit.md)
│     inventory (go list in the sandbox) → inventory.{json,md}, binding-table.md, coverage-ledger.json (planned)
│     estimate → estimate.json → the one profile question, with a cost range per profile
│     model completes binding-table.md, writes system-map.md   ◄ facts only, `?` when unknown
│     validate ledger · verifier provenance (abi, ceremony; deep: regen in the sandbox)
├─ P2 bundle --profile P → bundles/<ID>.md (+ threat model, loop memory)
│     budget check → zk-audit:hunter (≤ 6, Read/Grep/Glob) → agents save (+ tokens) → ledger mark
├─ P3 judging.md + severity-calibration.md → findings.json (draft)
├─ P4 budget check → git worktree add <out>/worktree → poc-builder → scripts/sandbox go test / forge
│     refuter (fp-check | zk-audit:refuter | brief) → evidence, confidence
├─ P5 critic-check → zk-audit:critic (lens-level gaps) → a decision per item → targeted wave → critic-check --verify
├─ loop: memory merge → NEW / KNOWN, seen k/N, stop rule → next pass or P6
└─ P6 ledger mark (close) → validate findings + ledger → assemble → REPORT.md   ◄ refuses invalid input, no clean claims
   budget stop at any wave → deferred units, partial REPORT.md
```

#### Recon, diff, resume

```text
/zk-audit recon   → P0 + P1 → prints stack, circuits, binding table, hints, footguns, questions; drafts zk-audit.md on yes
/zk-audit diff B  → gnark-inventory diff (git objects only: removed / conditional constraints, public inputs,
                    hints, gnark bumps, verifier and VK changes) → standard profile on the change
/zk-audit resume  → args resume (run.json) → status → first incomplete step; saved agents are not respawned
```

#### Report assembly

```text
assemble --out <out> --repo <repo>
├─ validate.DocumentWith(findings | ledger | stack, --out)   any error → exit 1, no file
├─ checkClaims                                   banned clean-claim phrases → exit 1
├─ loadRun                                       run.json, spend.json, agents/index.json, bundles/index.json, threat-model.json
├─ crossCheck                                    run_id, unknown fingerprints, open units, lines past EOF → warnings
└─ render                                        quotes via EvalSymlinks inside <repo>, coverage = covered only,
                                                 threat model, spend, partial notice, not-covered lines → MANIFEST.json
```

---

## 2. Threat & Trust Model

### Profile

> Classified as: **LLM agent orchestrator** with **untrusted-code analysis** and **code execution (PoC)** characteristics.

The audited repository is attacker-influenceable input that the system both
reads into model context and, in Phase 4 (and type loading in Phase 1),
compiles and runs.

### Actors & adversary model

| Actor | Trust level | Capabilities |
|---|---|---|
| User | Trusted | Chooses profile and budget, approves installs, network and permission prompts |
| Orchestrator (main session) | Bounded (by the session's permissions) | All session tools; writes `<out>`; spawns agents; runs scripts |
| Hunting agents, critics, refuter | Bounded (tool allow-list in a plugin install) | `zk-audit:hunter`, `zk-audit:critic`, `zk-audit:refuter`: `Read Grep Glob`; general-purpose limited by prompt in a standalone install |
| `zk-audit:poc-builder` | Bounded (prompt + sandbox) | `Read Grep Glob Write Edit Bash`; runs PoCs through `scripts/sandbox` by instruction |
| Audited repository | Untrusted | Source text, comments, `go.mod`, `foundry.toml`, package `init` code, symlinks, `zk-audit.md` |
| Companion skills | Bounded (third-party prompts) | Run inside the same session when installed; `solidity-auditor` runs on the scratch worktree and its output is converted to leads |
| Published `VERSION` file | Untrusted (display only) | Its content is printed only if it parses as a dotted number |

**Adversary ranking**

1. **Repository author** — the code under audit can steer every agent that reads it and runs code in Phase 4; the sandbox and read-only agent types now bound what it can make them do.
2. **Imperfect model** — skips or misreports steps whose rules are still prompt-level ([invariants.md](invariants.md) P-rules).
3. **Companion skill author** — a delegated skill's output becomes `findings.json` records (as leads, through `convert pashov`, for `solidity-auditor`).

### Trust boundaries

- **Audited repo → model context** — every agent reads target text; the binding table and `zk-audit.md` (as `threat-model.json`) are inlined into every bundle with the rule that they state intent and excuse nothing (P-8).
- **Audited repo → tool** — `inventory` re-runs itself in the sandbox for typed loading, with `CGO_ENABLED=0`, `GOWORK=off`, empty `GOFLAGS`, `GOPROXY=off`, `GOTOOLCHAIN=local` ([G-14](invariants.md#g-14)).
- **Audited repo → execution (P4, deep regen)** — PoCs and `verifier regen` compile and run target code inside `gnark-inventory sandbox`: no network, writes only to the worktree, home masked, memory and time limits ([G-26](invariants.md#g-26)); the PoC builder's use of the sandbox is by instruction ([P-3](invariants.md#p-3)).
- **Agents → target files** — read-only by tool allow-list for hunters, critics and the refuter in a plugin install; by prompt standalone ([P-1](invariants.md#p-1)).
- **Tool → filesystem** — writes only to `--out`; inside-repo outputs are refused, exit 2 ([G-16](invariants.md#g-16)).
- **Session → network** — the update check (one GET), and consented `--allow-network`, `go mod download`, `advisories --osv`, `verifier bytecode --rpc` ([P-7](invariants.md#p-7)).
- **Output location** — `<out>` under `~/.zk-audit`, outside the repo; repo writes only with `--file-output` or the recon `zk-audit.md` on yes (`SKILL.md` §3 rule 1).

### Key attack surfaces

- **PoC builder outside the sandbox** &nbsp;&#91;[P-3](invariants.md#p-3)&#93; — the poc-builder keeps Bash; trace whether every `go test` / `forge test` it runs goes through `scripts/sandbox`, and what a target can do when it does not.

- **Standalone installs** &nbsp;&#91;[P-1](invariants.md#p-1)&#93; — without plugin agent types, hunters are general-purpose agents told to use Read, Grep and Glob only.

- **macOS sandbox** &nbsp;&#91;[G-26](invariants.md#g-26)&#93; — `sandbox-exec` denies network and writes but not reads, and is not exercised in CI.

- **Model-written judgment** &nbsp;&#91;[G-8](invariants.md#g-8), [G-28](invariants.md#g-28)&#93; — coverage now needs saved outputs and recorded decisions, but whether an output really examined a unit is checked lexically.

- **Self-reported PoC results** &nbsp;&#91;[G-3](invariants.md#g-3)&#93; — the PoC file must exist and is hashed into `pocs/MANIFEST.json`; nothing re-runs it.

- **Threat-model steering** &nbsp;&#91;[G-24](invariants.md#g-24), [G-29](invariants.md#g-29)&#93; — `zk-audit.md` is repository text that tells agents whom to trust; the parser and the accepted-risk check keep it from removing records, not from biasing hunters.

---

## 3. Entry points

> Full map: **[entry-points.md](entry-points.md)** — 8 skill modes, 4 plugin
> commands, 4 agent roles (all plugin agent types), 25 CLI subcommands with
> their flags, 6 scripts and 18 developer entry points, each with what it
> reads and writes.

Skill flags (`--local`, `--loop N`, `--no-poc`, `--file-output`, `--out`,
`--profile`, `--budget`) are parsed by `gnark-inventory args`, which also
writes `run.json` for resume. CLI flags are Go `flag` sets; `TestDocumentedCommandsExist`
fails if a doc names one that does not exist.

---

## 4. End-to-end flow per phase

| Phase | Runs (file / agent / subcommand) | Reads | Writes | Gate |
|---|---|---|---|---|
| 0 Detect | `args --save`, `detect`, `preflight`, `sandbox --check`; `check-version`; companion detection | `<repo>` go.mod, imports, `.sol`, configs; module cache | `run.json`, `stack.json` | `args` refuses bad invocations (G-21); routes `.circom` / Noir / library / no-fit |
| 1 Recon | `threat-model`, `inventory` (sandbox), `estimate`, the profile question; orchestrator reads `inventory.md` and every `Define`; `validate ledger`; verifier provenance | `<repo>`, `zk-audit.md` | `threat-model.json`, `inventory.*`, `binding-table.md`, `system-map.md`, `coverage-ledger.json`, `estimate.json` | parser (G-29), ledger validator (G-1, G-7, G-8) |
| 2 Hunt | `bundle`, `budget check`, `zk-audit:hunter` per bundle, `agents save`, `ledger mark` | bundles, shard sources, gnark std | `bundles/`, `agents/`, `spend.json`, ledger statuses | `bundle` fails on zero bundles; budget stop (G-27); `ledger mark` (G-22) |
| 3 Judge | orchestrator with `judging.md`, `severity-calibration.md`, `rationalizations.md` | `agents/*.md`, `threat-model.json` | `findings.json` (draft) | validator (G-24, G-25) at P6 |
| 4 Prove | `budget check`; `git worktree add`; `zk-audit:poc-builder` via `scripts/sandbox`; refuter | findings, `poc-templates.md`, worktree | `pocs/`, `worktree/`, record `evidence` / `poc` / `refuter` | sandbox (G-26); G-3 |
| 5 Critique | `critic-check`, `zk-audit:critic`, targeted wave, `critic-check --verify`; loop: `memory merge` | ledger, inventory, `agents/` | `critic-check.json`, ledger decisions, `memory.json` | G-28, G-23 |
| 6 Report | `ledger mark` (close), `validate findings`, `validate ledger`, `assemble` | documents, run files, `<repo>` | `REPORT.md`, `pocs/MANIFEST.json`; `--file-output` copy in the repo | G-9, G-10, G-11 |

Profiles come from `profiles.json` (generated tables in `SKILL.md` and
`orchestration.md`): **quick** C1, I1, T1, G2 + 13 V-shards (1 pass, PoCs for
confirmed Critical/High circuit findings); **standard** C1–C6, I1–I4, S1, T1,
PR1, G2, F1 + 16 V-shards (critic + one wave); **deep** adds L1, G1, G3, A1,
3 passes with memory and verifier regeneration; **library** C1–C6, L1, G1,
G3, A1, F1 + 8 V-shards for gadget libraries.

### Concurrency

- At most six agents at a time (hunters, PoC builders, refuters), with an `Agent Progress` table (`orchestration.md` Turns 4, 6); prompt-only (P-5).
- The phase table and the agent table share status words (`Pending → Running → Done | Skipped | Blocked`), one phase `Running` (`SKILL.md` §4).
- `scripts/gnark-inventory` builds to a temp file and `mv`s it, keyed by a source hash, so parallel first calls do not see a half-written binary.
- `ledger mark`, `budget` and `spend.json` writes are atomic (temp file + rename); the orchestrator calls them one at a time.
- Inside the tool only `go/packages` runs in parallel (`errgroup`); everything else is single-threaded and sorted for determinism.
- Loop mode reruns Turns 3–7 per pass; `memory merge` refuses out-of-order passes.

---

## 5. Integrations

### Companion skills

Detection: the runtime's skill list first; fallback `find -L … -maxdepth 8` over
`~/.claude/skills`, `.claude/skills`, `~/.claude/plugins`, `~/.agents/skills`,
`~/.codex/skills` (`references/companions.md`). Installs are shown and run only
on a yes (`modes/setup.md`).

| Companion | Source | When called | Fallback | Wired to a turn |
|---|---|---|---|---|
| `circom-auditor` | zkSecurity | P0, `.circom` in scope | `generic-zk.md` vectors | yes (Phase 0) |
| `fp-check` | Trail of Bits | P4 refuter | `zk-audit:refuter` / brief | yes (Turn 6) |
| `spec-to-code-compliance` | Trail of Bits | C6 lens | C6 | yes (lens file) |
| `supply-chain-risk-auditor` | Trail of Bits | I4 lens | `gnark-versions.md` | yes (lens file) |
| `differential-review` | Trail of Bits | diff mode | standard profile on the change | yes (`modes/diff.md`) |
| `solidity-auditor`, `x-ray` | pashov | Solidity beyond the ZK surface; threat model | S1 + V-contract (standard, deep); I1–I3 in quick | `solidity-auditor`: Turn 4 on the scratch worktree, `convert pashov`; `x-ray`: none |
| `audit-context-building`, `vulnerability-triage-brocards`, `variant-analysis`, `static-analysis`, `building-secure-contracts`, `property-based-testing`, `mutation-testing` | Trail of Bits | deep context, triage, variants, Semgrep/CodeQL, Slither, oracle tests | recon, `rationalizations.md`, grep `inventory.json`, skip and note | no call site |
| zkao CLI | zkSecurity (paid) | deep profile, suggestion only | — | no |

Delegated results become `findings.json` records with `detected_by:
<companion>`; `solidity-auditor` output goes through `gnark-inventory convert
pashov` (every item a lead), the others by instruction.

### External tools

| Tool | Used by | When | Without it |
|---|---|---|---|
| `go` ≥ 1.24 (or `ZK_AUDIT_GO`) | wrapper build; typed loading; PoCs; `verifier regen`; `make` | P0, P1, P4 | no inventory, no PoCs |
| `bwrap` (Linux) / `sandbox-exec` (macOS) | `gnark-inventory sandbox` | P1 type loading, P4, deep regen | limits only, with a warning (said in the report's posture) |
| `git` | worktrees for PoCs; `diff` reads git objects | P4, diff | PoCs disabled |
| `forge` | contract PoCs (`T-FOUNDRY-*`) | P4 | contract findings stay `ANALYSIS` |
| `claude` CLI | `claude plugin validate`, `claude plugin tag` (CI, release) | development | — |
| `semgrep`, `slither` | only through `static-analysis` / `building-secure-contracts` companions | — | skipped, noted under coverage |
| `curl`, `bash` | `check-version`, all wrappers | Turn 1, setup | update check silently skipped |

---

## 6. Invariants

> ### Full invariant map: **[invariants.md](invariants.md)**
>
> - **29 runtime guards** (`G-1` … `G-29`) — checks in the tool that refuse or warn
> - **19 test-enforced rules** (`T-1` … `T-19`) — sync, docs and KB lint, fixtures, version matrix, cost model, CI hygiene
> - **21 prompt-level rules** (`P-1` … `P-21`) — 10 still `No`, the rest `Partial` or now enforced by code
>
> Since `4d9cf86`: P-1, P-14, P-15, P-17 and P-18 moved to enforced (in a plugin install for P-1), P-3, P-7 and P-12 to partial; G-3, G-8, G-11, G-13, G-14 and G-16 were tightened; G-21 … G-29 and T-14 … T-19 are new.

---

## 7. Documentation quality

| Aspect | Status | Notes |
|---|---|---|
| README | Present | Scope, properties, install (both routes), use, status table with measured runs, the pilot line and the development targets. |
| Design | `PLAN.md`, `docs/design-notes.md`, `docs/research.md`, `docs/licence-options.md`, `docs/pilots.md` | Every deviation and decision recorded; licence and pilots are owner decisions with written options. |
| Changes | `CHANGELOG.md` (Keep a Changelog) | Unreleased section for shramee/zk-audit#8 to #16; release notes come from it. |
| Per-component | `plugins/zk-audit/README.md`, `evals/README.md`, Go package comments | — |
| Attribution | `NOTICE` + per-file headers for adapted MIT text | Trail of Bits text is not copied |
| Docs-vs-code checks | T-5 … T-10, T-14, T-16 | A doc naming a missing script, subcommand, flag, reference or path fails `go test`; generated profile tables cannot drift |

---

## 8. Test, CI and eval surface

| Metric | Value | Source |
|---|---|---|
| Go test functions | 167 in 41 test files (tool), plus the scorer's | file scan |
| Go test lines | 6,597 (tool) | file scan |
| Golden files | 3 (`testdata/assemble/{full,empty,partial}`) | `TestGoldenFull`, `TestGoldenEmpty`, `TestGoldenPartial` |
| Fixtures | 11 in `testdata/` (pool, edge, lib-gadgets, liveness-roots, sol-gnark-abi, sol-inherit, sol-library, sol-multi, pashov runs, OSV replays, assemble goldens) | typed tests need `make fixtures` |
| Coverage % | tool 73.9 %, scorer 73.3 % (local, 2026-10-29, typed fixtures cached); CI floor 65 % | `make cover`, CI job summary and artifact |

| Category | Count / where | Notes |
|---|---|---|
| Unit | 31 of 34 tool packages have tests; `agents`, `report`, `fixture` are covered through callers | `go test ./...` |
| Docs / KB lint | docs tests + `lint-kb` (111 vectors, calibration, advisories) | T-5 … T-10, T-14, T-16 |
| Typed integration | `make test-types` (gnark v0.14.0 fixtures) | CI `check`, network |
| Sandbox | network, write, memory, time, go and forge inside bubblewrap | CI `check` with `ZK_AUDIT_REQUIRE_SANDBOX=1` |
| Executed PoCs | `make eval-pocs`: pool and lib-gadgets (Go), liveness-roots and sol-gnark-abi (Foundry, against a real exported verifier) | CI `check` |
| Version matrix | `test/versions/run` on gnark v0.10.0, v0.14.0, v0.16.4 | CI `versions` |
| Plugin and release hygiene | gofmt, `claude plugin validate`, `make release-check`, release workflow on `zk-audit--v*` tags | CI `check`, `plugin`; `release.yml` |
| Install smoke | `make standalone` (skill folder alone) | CI `check` |
| Model evals | Blind runs on the pool fixture, 2026-10-29, one per profile at `e198ed7`: quick 12/14, standard 12/14, deep 13/14 (2 partial), 0 false positives; 9.16, 26.09 and 25.64 USD ([`evals/baseline/pool-2026-10-29.md`](../../evals/baseline/pool-2026-10-29.md)) | manual (`evals/run-audit`), not in CI; one run each, no variance |
| Pilots beside a human auditor | none run ([`docs/pilots.md`](../pilots.md)) | — |
| Fuzz / property | none | — |

CI (`.github/workflows/ci.yml`, actions pinned to exact versions): job
`check` (gofmt, offline `make check`, `make test-types`, coverage with a
floor, Foundry, `make eval-pocs`), job `plugin` (Claude Code CLI 2.1.312,
`claude plugin validate`, `make release-check`), job `versions` (matrix of
three gnark releases); `permissions: contents: read`. `release.yml` runs on
release tags with `contents: write`.

### Gaps

- No scored model eval in CI (the `ci-smoke` case is in shramee/zk-audit#12, open); every profile measured once, before T1, PR1, S1, library mode, loop memory, budget and critic-check existed.
- No pilot beside a human auditor yet.
- macOS sandbox path not exercised in CI.
- No fuzzing; the jsonschema package is a hand-written subset of draft 2020-12.

---

## 9. Developer & git history

> Repo shape: 144 commits on `feat/product-ops` (127 on `main`), 2026-10-25 → 2026-10-30 (commit dates), 11 merged pull requests (shramee/zk-audit#4 to #11, #13 to #15); #12 and #16 open.

| Signal | Value | Assessment |
|---|---|---|
| Contributors | 1 author (`shramee`, two name spellings), model co-authored commits | single maintainer |
| Merge commits | 12 of 144 | PR flow; no second reviewer visible |
| Conventional commits | 131 of 132 non-merge subjects typed (62 `feat`, 32 `docs`, 15 `fix`, 13 `test`, 3 `refactor`, 3 `ci`, 3 `chore`; the first is `init`) | consistent |
| Hotspots | `SKILL.md` (36), `docs/design-notes.md` (29), `main.go` (22), `orchestration.md` (20), `README.md` (18), `Makefile` (16) | prompts and the CLI front door churn most |

- **Measurement-driven work** — the 2026-10-29 runs (shramee/zk-audit#10) produced a fix list; most of shramee/zk-audit#11, #13, #14 and #16 trace an item to it (loop memory, agent recovery, allowlist-safe commands, the eddsa KB fix, the ABI check, trusted parties, evidence schema, severity calibration, ledger tools, critic with teeth, refuter policy).
- **Prompt files are still the hotspot**, now with more executable checks around them (generated tables, docs lint, read-only agent types).

---

## Worth investigating

Design weak spots, in priority order. Investigation pointers, not findings.
Items from the `4d9cf86` snapshot keep their numbers; resolved ones say by
which pull request.

1. ~~**PoC runs execute target code without an OS sandbox**~~ — resolved by shramee/zk-audit#11 (`gnark-inventory sandbox`, bubblewrap on Linux); what remains is P-3: the poc-builder keeps Bash and uses the sandbox by instruction, and macOS does not restrict reads ([P-3](invariants.md#p-3), [G-26](invariants.md#g-26)).
2. ~~**Hunters are general-purpose agents**~~ — resolved for plugin installs by shramee/zk-audit#11 (`zk-audit:hunter`, `zk-audit:critic`); standalone installs still restrict tools by prompt ([P-1](invariants.md#p-1)).
3. ~~**`go list` on untrusted repos**~~ — resolved by shramee/zk-audit#11 (environment pinned, typed loading in the sandbox) ([G-14](invariants.md#g-14)).
4. ~~**Ledger truthfulness is unchecked**~~ — resolved by shramee/zk-audit#11 (saved outputs and reviewed paths checked with `--out`), extended by shramee/zk-audit#16 (`critic-check`); substance is still lexical ([G-8](invariants.md#g-8)).
5. ~~**PoC evidence is self-reported**~~ — resolved for the file by shramee/zk-audit#11 (`poc.path` under `<out>/pocs/`, `MANIFEST.json`); nothing re-runs a PoC ([G-3](invariants.md#g-3)).
6. ~~**Answer keys ship in installs**~~ — resolved by shramee/zk-audit#8 (`evals/`, `testdata/` at the root, T-15) ([P-14](invariants.md#p-14)).
7. ~~**Profiles are defined four times**~~ — resolved by shramee/zk-audit#11 (`profiles.json`, generated tables, T-14) ([P-17](invariants.md#p-17)).
8. ~~**Inside-repo writes only warn**~~ — resolved by shramee/zk-audit#11 (refused, exit 2) ([G-16](invariants.md#g-16)).
9. ~~**Symlinked quotes**~~ — resolved by shramee/zk-audit#11 (`EvalSymlinks`) ([G-13](invariants.md#g-13)).
10. **Update check is default-on** — unchanged by design: one GET of `VERSION`, nothing about the target, `ZK_AUDIT_NO_UPDATE_CHECK=1` turns it off ([G-19](invariants.md#g-19)).
11. ~~**Binary cache keyed by version + mtime**~~ — resolved by shramee/zk-audit#9 (source hash in the binary name).
12. ~~**Prompt-only features**~~ — mostly resolved: loop memory and diff triggers by shramee/zk-audit#11, the companion converter by shramee/zk-audit#14, missing units by shramee/zk-audit#16; running each pass and each wave in full is still the orchestrator's ([P-18](invariants.md#p-18)).
13. **No measured run since the follow-up list** — every lens, tool and rule added in shramee/zk-audit#11 to #16 is tested in code but none has been exercised by an end-to-end audit; recall, cost and the estimate's calibration may have moved.
14. **Spend is an estimate** — the runtime shows tokens for some agents and cost for none; the budget stops on calibrated USD, so a run can overshoot its ceiling by the estimate's error ([G-27](invariants.md#g-27), [P-20](invariants.md#p-20)).
15. **Lexical critic matching** — `critic-check` counts an item as examined when an output cites its line or names it; an output that names a hint without analysing it passes ([G-8](invariants.md#g-8), [G-28](invariants.md#g-28)).
16. **Threat-model text reaches every bundle** — `zk-audit.md` is repository-controlled; its trust levels and accepted risks are framed as intent, and accepted risks are validated, but a misleading file can still bias hunters ([G-29](invariants.md#g-29)).
17. **No licence** — the plugin directory refuses a submission without one; the options are in [`docs/licence-options.md`](../licence-options.md).

---

## X-Ray Verdict

**ADEQUATE** for the deterministic half and for isolation in a Linux plugin install; agent behaviour since the follow-up list is unmeasured.

| Axis | Tier | Basis |
|---|---|---|
| Tests | ADEQUATE (tool) / FRAGILE (agent behaviour) | Unit, golden, docs/KB lint, typed fixtures, sandbox tests, executed Go and Foundry PoCs, version matrix, coverage floor, install smoke in CI; three manual model runs before the latest changes, none in CI, no pilot |
| Docs | ADEQUATE | README, PLAN, design notes, CHANGELOG, licence options, pilot protocol, NOTICE, docs-vs-code tests, generated tables |
| Robustness | ADEQUATE (Linux plugin install) / FRAGILE (standalone, macOS) | Read-only agent types, OS sandbox, refused repo writes, validators that check evidence on disk, budget and critic gates; 10 prompt-only rules remain, including the poc-builder's sandbox use |

**Structural facts:**
1. 21,158 Go lines in 34 packages with one external module family (`golang.org/x/{tools,mod,sync}`, vendored); 167 Go tests in the tool.
2. 6,362 lines of prompts and knowledge base: 20 lens files, 111 sourced vectors in 16 slices, 21 calibration anchors, 23 footgun detector rules, 14 embedded advisories.
3. 29 runtime guards and 19 test-enforced rules versus 21 prompt-level rules, 10 of them still `No` (invariants.md).
4. Three recorded blind end-to-end runs (2026-10-29): quick 12/14, standard 12/14, deep 13/14 on the pool fixture, 0 false positives; no pilot.
5. Single maintainer, 144 commits in six days of commit dates, 11 merged pull requests.
