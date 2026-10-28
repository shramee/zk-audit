# Entry Point Map

> zk-audit | 6 skill modes + 3 plugin commands | 4 agent roles (2 plugin agent types) | 10 CLI subcommands | 5 scripts | 8 developer entry points

Paths: `{skill}` = `plugins/zk-audit/skills/zk-audit/` (self-contained; also
`~/.claude/skills/zk-audit/` in a standalone install). `<out>` =
`~/.zk-audit/<repo>/<run-id>/` or `--out`. `<repo>` = the audited repository.
"Prompt" means the behaviour is an instruction to the model, not code.

---

## Flow paths

```text
Full audit
  /zk-audit [profile] [paths] [flags]
    → SKILL.md §1 mode = full audit                      ◄── request says audit / review / find bugs
    → P0 scripts/gnark-inventory detect                  ◄── Go ≥ 1.24 on PATH (first run builds the tool)
    → P1 scripts/gnark-inventory inventory → validate ledger
    → P2 scripts/gnark-inventory bundle → hunting agents  ◄── profile answer (one AskUserQuestion)
    → P3 judging (model) → findings.json draft
    → P4 poc-builder → go test / forge in <out>/worktree ◄── git worktree; not --no-poc
         refuter / fp-check
    → P5 coverage critic → targeted wave (standard, deep)
    → P6 validate findings + ledger → assemble → REPORT.md
         [--file-output] cp REPORT.md <repo>/zk-audit-report-<run-id>.md

Recon        /zk-audit recon | /zk-audit:recon  → P0 + P1 only → printed tables (+ zk-audit.md on yes)
Diff         /zk-audit diff  | /zk-audit:diff   → two worktrees → inventory ×2 → compare → standard profile on the change
Setup        /zk-audit setup | /zk-audit:setup  → detection commands → tool build → update check → table → installs on yes
Guidance     plain question                     → answer from references/ + code; no agents, no <out>
```

---

## Skill (model-facing)

### `zk-audit` skill (`{skill}/SKILL.md`)

| Item | Value |
|---|---|
| Name / invocation | `/zk-audit` (standalone, or where short names resolve); `/zk-audit:zk-audit` in a plugin install (listed that way by a headless session, `docs/pashov-parity.md`) |
| Trigger text | frontmatter `description`: audit, review, security-check or find bugs in gnark circuits, a ZK verifier integration, a Groth16/PLONK verifier contract, a gnark version bump; `/zk-audit`, `/zk-audit recon`, `/zk-audit diff`, `/zk-audit setup` |
| `allowed-tools` | none (deliberate, `docs/design-notes.md` "Packaging") |
| Arguments | profile `quick` · `standard` (default) · `deep`; scope paths; mode word `recon` · `diff <base>[..<head>]` · `setup [--check-only]` |
| Flags (prompt-level, parsed by the model) | `--local` (no subagents) · `--loop N` (deep default 3) · `--no-poc` · `--file-output` · `--out DIR` |
| Reads | `{skill}/references/**` on demand (SKILL.md §8), `{skill}/VERSION`, `<repo>` source, `<repo>/zk-audit.md` if present |
| Writes | everything under `<out>`; into `<repo>` only `zk-audit-report-<run-id>.md` (`--file-output`) and `zk-audit.md` (recon, after yes) — SKILL.md §3 rule 1 |
| Asks | one `AskUserQuestion` before the first spawn (profile and model), or states the default |
| Network | `scripts/check-version` (one GET); anything else only with consent |

### Modes (SKILL.md §1)

| Mode | Selected when | Spawns agents | Writes `<out>` | Procedure |
|---|---|---|---|---|
| guidance | a question ("is this circuit ok?", "what does X constrain?"), or ambiguous | no | no | SKILL.md §1 |
| full audit | "audit", "review", "find bugs", `/zk-audit …` | yes | yes | SKILL.md §4, `references/orchestration.md` |
| recon | `/zk-audit recon`, `/zk-audit:recon` | no | yes | `references/modes/recon.md` |
| diff | `/zk-audit diff`, `/zk-audit:diff` | yes | yes (+ 2 worktrees) | `references/modes/diff.md` |
| setup | `/zk-audit setup`, `/zk-audit:setup` | no | no (builds `~/.zk-audit/bin`) | `references/modes/setup.md` |
| not this skill | "fix this test", "write a circuit" | no | no | SKILL.md §1 |

## Plugin commands (`plugins/zk-audit/commands/`, plugin install only)

Each is a thin wrapper that sets `{skill}` = `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`
and follows the mode file (`TestCommandPathsExist` checks the path exists).

| Command | `argument-hint` | `allowed-tools` | Follows |
|---|---|---|---|
| `/zk-audit:setup` | `[--check-only]` | `Bash Read Glob AskUserQuestion` | `references/modes/setup.md` |
| `/zk-audit:recon` | `[path ...]` | (not restricted) | `references/modes/recon.md` |
| `/zk-audit:diff` | `<base>[..<head>]` | (not restricted) | `references/modes/diff.md` |

## Agents

| Agent | Type | Tools | Reads | Writes | Spawned in |
|---|---|---|---|---|---|
| Hunting agents (C1–C6, I1–I4, 12 `V-*`, G1–G3, A1, F1) | general-purpose (no plugin agent type) | whatever the session grants; read-only by prompt | `<out>/bundles/<ID>.md`, the source shard in `<repo>`, gnark std in the module cache | nothing (return text; the orchestrator saves `<out>/agents/<ID>.md`) | P2, P5 targeted wave (`orchestration.md` Turns 4, 7) |
| `zk-audit:poc-builder` | plugin agent; general-purpose briefed with `{skill}/agents/poc-builder.md` in a standalone install | `Read Grep Glob Write Edit Bash` | the finding, `poc-templates.md`, `<repo>` via the worktree, `stack.json`, gnark source in the module cache | `<out>/pocs/<n>_poc_test.go` (or `.t.sol`), a copy in `<out>/worktree/<pkg>/` | P4 (`orchestration.md` Turn 6) |
| `zk-audit:refuter` | plugin agent; `fp-check` if installed; general-purpose briefed with `{skill}/agents/refuter.md` otherwise | `Read Grep Glob` (plugin agent only) | the finding, `<repo>` source, gnark std | nothing | P4 |
| Coverage critic | general-purpose, inline prompt in `orchestration.md` Turn 7 | session tools | `coverage-ledger.json`, `inventory.md`, `binding-table.md`, `<out>/agents/` | nothing (returns `missing_units` JSON) | P5 |

---

## CLI: `gnark-inventory` (`{skill}/tools/gnark-inventory`, `main.go`)

Run through `{skill}/scripts/gnark-inventory`. Exit status: 0 ok, 1 validation
or lint failure, 2 usage or I/O error (`main.go` usage text).

| Subcommand and flags | Reads | Writes | Notes |
|---|---|---|---|
| `detect [--repo DIR=.] [--out FILE]` | every `go.mod` (`internal/gomod`), `.go` imports only (`parser.ImportsOnly`), `.sol` (`internal/solidity`), `foundry.toml`, `hardhat.config.*`, `Nargo.toml`, `.circom` counts; embedded advisories | `stack.json` (or stdout); prints the stack line | `internal/detect/detect.go:93` |
| `inventory --repo DIR --out DIR [--files a,b/] [--syntax-only] [--allow-network]` | all `.go` via `go/packages` (runs `go list` in the target, `GOPROXY=off` unless `--allow-network`) with `go/parser` fallback; `.sol` | `inventory.json`, `inventory.md`, `binding-table.md` (draft), `coverage-ledger.json` (all `planned`), `stack.json` | warns if `--out` is inside the repo (`main.go:177`) |
| `bundle --out DIR --skill SKILL_DIR [--profile quick\|standard\|deep]` | `<out>/inventory.json`, `<out>/binding-table.md`, `references/senior-auditor-sop.md`, `shared-rules.md`, lens and slice files; source files for line counts and backend imports | `<out>/bundles/<ID>.md`, `<out>/bundles/index.json`; prints a table | error when no bundle is written (`main.go:288`) |
| `validate findings FILE` | FILE, embedded `findings.schema.json` | stdout | schema + semantic rules (`internal/validate/validate.go:102`) |
| `validate ledger FILE` | FILE, embedded `ledger.schema.json` | stdout | `validate.go:173` |
| `validate stack FILE` | FILE, embedded `stack.schema.json` | stdout | schema only; counts 1 item |
| `assemble --out DIR [--findings F] [--ledger F] [--stack F] [--inventory F] [--repo DIR] [--report F]` | findings, ledger (required), stack, inventory (if present), `<repo>` files for quotes | `REPORT.md` (or `--report`); nothing on invalid input (exit 1) | `internal/assemble/assemble.go:64`; warns if `--report` is inside the repo (`main.go:372`) |
| `lint-kb [--gnark-src DIR] SKILL_DIR` | `SKILL.md`, `references/**`, embedded advisories and rule ids; optional gnark checkout | stdout | `internal/kblint/kblint.go:69` |
| `advisories [--version vX.Y.Z]` | embedded `advisories.json` | stdout JSON | `internal/advisory` |
| `rules` | embedded rule table | stdout JSON (23 footgun rules) | `internal/inventory/footguns.go:22` |
| `version` · `--version` · `-v` / `help` · `-h` · `--help` | — | stdout | `Version` = `0.1.0` |

## Scripts (`{skill}/scripts/`)

| Script | Does | Env | Reads / writes |
|---|---|---|---|
| `gnark-inventory` | builds the tool once per version (`GOWORK=off GOFLAGS=-mod=vendor go build -trimpath`), rebuilds when a source `.go` is newer than the binary, then `exec`s it | `ZK_AUDIT_BIN` (default `~/.zk-audit/bin`) | writes `gnark-inventory-<ver>` via a temp file + `mv` |
| `validate-findings`, `validate-ledger` | `gnark-inventory validate findings\|ledger "$@"` | — | — |
| `assemble` | `gnark-inventory assemble "$@"` | — | — |
| `check-version` | compares `{skill}/VERSION` with the published one; one line only when local is older; always exit 0 | `ZK_AUDIT_NO_UPDATE_CHECK`, `ZK_AUDIT_VERSION_URL` | one HTTPS GET (3 s) |

---

## Developer entry points (not shipped behaviour)

| Entry | Does | Network |
|---|---|---|
| `make check` | `vet`, `test`, `lint-kb`, `standalone` (CI step 1, run with `GOFLAGS=-mod=vendor GOPROXY=off`) | no |
| `make test-types` | `fixtures` (`go mod download` for `testdata/pool`, `testdata/edge`) then typed-mode inventory tests with `ZK_INVENTORY_REQUIRE_TYPES=1` | yes |
| `make eval-pocs` | `evals/run-pocs pool <tmp>`: sanitized copy, eval PoCs, `go test -run '^Test(PoC\|Decoy)_'` | yes (`EVAL_GOPROXY`) |
| `make standalone` | `test/standalone-skill.sh`: skill folder alone in a throwaway `~/.claude/skills`, full deterministic pipeline | no |
| `make sync-schemas`, `make sync-agents` | copy canonical schemas into the tool's embed dir; skill agent briefs into `plugins/zk-audit/agents/` | no |
| `make vendor` | `go mod tidy && go mod vendor` | yes |
| `plugins/zk-audit/evals/sanitize <fixture> <dest>` | copy a fixture outside the repo, strip hint comments, fail if hint text survives, init a one-commit git repo | no |
| `test/parity/*.sh` | install / discovery checks in a throwaway `HOME`; `live-*.sh` call `claude -p` and spend money (`MODEL` required) | `live-*` only |
