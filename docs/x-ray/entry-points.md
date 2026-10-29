# Entry Point Map

> zk-audit | 8 skill modes + 4 plugin commands | 4 agent roles (4 plugin agent types) | 25 CLI subcommands | 6 scripts | 18 developer entry points

Paths: `{skill}` = `plugins/zk-audit/skills/zk-audit/` (self-contained; also
`~/.claude/skills/zk-audit/` in a standalone install). `<out>` =
`~/.zk-audit/<repo>/<run-id>/` or `--out`. `<repo>` = the audited repository.
"Prompt" means the behaviour is an instruction to the model, not code.
Refreshed 2026-10-29 for the tree after shramee/zk-audit#16; the snapshot of
`4d9cf86` is in git history.

---

## Flow paths

```text
Full audit
  /zk-audit [profile] [paths] [flags]
    → gnark-inventory args --save                        ◄── words parsed by code; run.json written
    → SKILL.md §1 mode = full audit                      ◄── request says audit / review / find bugs
    → P0 detect · preflight · sandbox --check            ◄── Go ≥ 1.24 on PATH (first run builds the tool)
    → P1 threat-model · inventory (go list in the sandbox)
         estimate → one AskUserQuestion (profile, model, cost range per profile)
         binding table, system map (model) · validate ledger · verifier provenance
    → P2 bundle → budget check → zk-audit:hunter ×N      ◄── ≤ 6 at once; agents save + ledger mark
    → P3 judging (model) → findings.json draft
    → P4 budget check → poc-builder → scripts/sandbox go test / forge in <out>/worktree
         refuter / fp-check                              ◄── PoCs off with --no-poc (refuter still runs)
    → P5 critic-check → zk-audit:critic → targeted wave → critic-check --verify
    → (loop mode) memory merge → next pass or stop
    → P6 ledger mark (close) → validate findings + ledger → assemble → REPORT.md
         [--file-output] <repo>/zk-audit-report-<run-id>.md
    budget stop at any wave → close the ledger → partial REPORT.md

Recon        /zk-audit recon | /zk-audit:recon    → P0 + P1 only → printed tables (+ zk-audit.md from the template on yes)
Diff         /zk-audit diff  | /zk-audit:diff     → gnark-inventory diff (git objects only) → standard profile on the change
Library      /zk-audit library                    → full audit with the library profile; harness for PoCs
Resume       /zk-audit resume | /zk-audit:resume  → args resume → status → first incomplete step
Setup        /zk-audit setup | /zk-audit:setup    → detection commands → tool build → update check → table → installs on yes
Guidance     plain question                       → answer from references/ + code; no agents, no <out>
```

---

## Skill (model-facing)

### `zk-audit` skill (`{skill}/SKILL.md`)

| Item | Value |
|---|---|
| Name / invocation | `/zk-audit` (standalone, or where short names resolve); `/zk-audit:zk-audit` in a plugin install |
| Trigger text | frontmatter `description`: audit, review, security-check or find bugs in gnark circuits, a ZK verifier integration, a Groth16/PLONK verifier contract, a gnark version bump; `/zk-audit`, `/zk-audit recon`, `/zk-audit diff`, `/zk-audit setup` |
| `allowed-tools` | none (deliberate, `docs/design-notes.md` "Packaging") |
| Arguments | profile `quick` · `standard` (default) · `deep` · `library`; scope paths; mode word `recon` · `diff <base>[..<head>]` · `setup [--check-only]` · `resume [run-id\|out-dir]` |
| Flags (parsed by `gnark-inventory args`) | `--local` · `--loop N` (1–10; deep default 3) · `--no-poc` · `--file-output` · `--out DIR` · `--profile P` · `--budget USD` |
| Reads | `{skill}/references/**` on demand (SKILL.md §8), `{skill}/VERSION`, `<repo>` source, `<repo>/zk-audit.md` (through `threat-model`) |
| Writes | everything under `<out>`; into `<repo>` only `zk-audit-report-<run-id>.md` (`--file-output`) and `zk-audit.md` (recon, after yes) — SKILL.md §3 rule 1 |
| Asks | one `AskUserQuestion` after the inventory, with the estimate (profile and model), or states the default |
| Network | `scripts/check-version` (one GET); module downloads, `advisories --osv` and `verifier bytecode --rpc` only with consent |

### Modes (SKILL.md §1)

| Mode | Selected when | Spawns agents | Writes `<out>` | Procedure |
|---|---|---|---|---|
| guidance | a question ("is this circuit ok?", "what does X constrain?"), or ambiguous | no | no | SKILL.md §1 |
| full audit | "audit", "review", "find bugs", `/zk-audit …` | yes | yes | SKILL.md §4, `references/orchestration.md` |
| library | `/zk-audit library`, or `stack.json` `library.mode` | yes | yes | `references/modes/library.md` |
| recon | `/zk-audit recon`, `/zk-audit:recon` | no | yes | `references/modes/recon.md` |
| diff | `/zk-audit diff`, `/zk-audit:diff` | yes | yes | `references/modes/diff.md` |
| resume | `/zk-audit resume`, `/zk-audit:resume` | the missing ones only | continues `<out>` | `references/modes/resume.md` |
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
| `/zk-audit:resume` | `[run-id\|out-dir] [--budget USD]` | (not restricted) | `references/modes/resume.md` |

## Agents

| Agent | Type | Tools | Reads | Writes | Spawned in |
|---|---|---|---|---|---|
| Hunting agents (lenses and V-shards of `profiles.json`) | `zk-audit:hunter`; general-purpose briefed with `{skill}/agents/hunter.md` in a standalone install | `Read Grep Glob` (plugin agent type; by prompt standalone) | `<out>/bundles/<ID>.md`, the source shard in `<repo>`, gnark std at the absolute path the bundle names | nothing (return text; the orchestrator saves it with `agents save`) | P2, P5 targeted wave |
| `zk-audit:critic` | plugin agent; general-purpose briefed with `{skill}/agents/critic.md` | `Read Grep Glob` | `critic-check.json`, `coverage-ledger.json`, `inventory.md`, `binding-table.md`, `system-map.md`, `threat-model.json`, `<out>/agents/` | nothing (returns JSON) | P5 (coverage), deep final-clean |
| `zk-audit:poc-builder` | plugin agent; general-purpose briefed with `{skill}/agents/poc-builder.md` | `Read Grep Glob Write Edit Bash` | the finding, `poc-templates.md`, `<repo>` via the worktree, `stack.json`, gnark source in the module cache | `<out>/pocs/<n>_poc_test.go` (or `.t.sol`), a copy in `<out>/worktree/<pkg>/`; runs it through `scripts/sandbox` (by prompt) | P4 |
| `zk-audit:refuter` | plugin agent; `fp-check` if installed; general-purpose briefed with `{skill}/agents/refuter.md` otherwise | `Read Grep Glob` | the finding, `<repo>` source, gnark std | nothing | P4 |

---

## CLI: `gnark-inventory` (`{skill}/tools/gnark-inventory`, `main.go`)

Run through `{skill}/scripts/gnark-inventory`. Exit status: 0 ok, 1
validation or lint failure, 2 usage or I/O error; `sandbox` returns the
command's status, 124 on the time limit, 125 when the sandbox cannot be set
up, 127 when the command does not exist.

| Subcommand and flags | Reads | Writes | Notes |
|---|---|---|---|
| `args [--repo DIR] [--mode M] [--run-id ID] [--home DIR] [--save] -- WORDS` | words, scope paths | stdout JSON; `<out>/run.json` with `--save` | rejects unknown flags, scope outside the repo, `--out` inside it; `resume` reads `run.json` back |
| `detect --repo DIR [--out FILE]` | every `go.mod`, `.go` imports, `.sol`, Foundry / Hardhat / Noir / Circom markers; embedded advisories | `stack.json` | library detection (`library.mode`) |
| `preflight --repo DIR [--out DIR] [--json]` | the module cache, `go env GOVERSION` | stdout (download commands, `use_go`) | runs nothing it prints |
| `threat-model --repo DIR [--out DIR] [--file F] [--json]` | `<repo>/zk-audit.md` | `<out>/threat-model.json` | exit 1 on malformed entries; no file is not an error |
| `inventory --repo DIR --out DIR [--files a,b/] [--syntax-only] [--allow-network] [--sandbox auto\|on\|off]` | all `.go` (typed via `go list` in the sandbox, syntax fallback), `.sol` | `inventory.json`, `inventory.md`, `binding-table.md`, `coverage-ledger.json`, `stack.json` | refuses `--out` inside the repo (exit 2) |
| `estimate --out DIR [--profile P]... [--passes N] [--no-poc] [--json]` | `<out>/inventory.json`, shard sources | `<out>/estimate.json`; table | calibrated on the 2026-10-29 runs |
| `bundle --out DIR --skill SKILL_DIR [--profile P]` | inventory, binding table, threat model, memory, references | `<out>/bundles/<ID>.md`, `bundles/index.json` | error when no bundle is written |
| `profiles [--profile P] [--markdown] [--check-docs DIR] [--sync-docs DIR]` | embedded `profiles.json` | stdout; the generated doc tables with `--sync-docs` | |
| `agents save --out DIR --id ID [--from F] [--status S] [--reason R] [--tokens N] [--tool-uses N] [--duration-ms N] [--model M] [--role R]` · `agents list` | the agent's return | `<out>/agents/<ID>.md`, `agents/index.json`, `spend.json` | attempts counted |
| `ledger mark\|add\|show --out DIR …` | `coverage-ledger.json` | the ledger, atomically | validated with the `--out` checks first |
| `budget record\|check\|show --out DIR …` | `spend.json`, `run.json` | `spend.json` | `check` stops before a wave that crosses `--budget` |
| `status --out DIR [--json]` | everything in `<out>` | stdout | resume |
| `critic-check --out DIR [--verify] [--json]` | ledger, inventory, `agents/` | `critic-check.json` | `--verify` exit 1 while an item has no decision |
| `memory init\|merge\|known\|status --out DIR …` | `memory.json`, `passes/<p>/findings.json`, critic output | `memory.json`, cumulative `findings.json` | NEW / KNOWN, seen k/N, stop rule |
| `validate findings\|ledger\|stack\|threat-model FILE [--out DIR]` | FILE, embedded schemas; with `--out`, PoC files, agent outputs, the threat model | stdout | |
| `assemble --out DIR [--findings F] [--ledger F] [--stack F] [--inventory F] [--repo DIR] [--report F] [--file-output]` | the documents, `run.json`, `spend.json`, `agents/index.json`, `bundles/index.json`, `threat-model.json`, `<repo>` quotes | `REPORT.md`, `pocs/MANIFEST.json`; nothing on invalid input (exit 1) | `--report` inside the repo refused (exit 2) |
| `diff --repo DIR --base REV [--head REV] [--out DIR]` | git objects of `<repo>` | `diff.json`, `diff.md` | no worktree, hooks or diff drivers |
| `verifier abi\|diff\|vk\|bytecode\|regen\|ceremony …` | verifier sources, VK files, deployed bytecode files; `--rpc` only on request | stdout; `regen` writes `<out>/regen/` | `regen` runs gnark in the sandbox |
| `convert pashov --in PATH --out FILE [--inventory FILE]` | `solidity-auditor` run files | the converted records | all `lead` |
| `harness --out DIR (--gadget ID\|NAME \| --all) [--worktree DIR] [--print] [--emparams T] [--curve C]` | `inventory.json` | wrapper circuit files | refuses a destination inside the repo |
| `sandbox [--rw DIR]... [--ro DIR]... [--cwd DIR] [--timeout SEC] [--mem MB] [--allow-network] [--engine E] [--require] [--check] -- CMD` | — | only the `--rw` dirs | bubblewrap / `sandbox-exec` / limits only |
| `lint-kb [--gnark-src DIR] SKILL_DIR` | `SKILL.md`, `references/**`, embedded advisories, calibration and rule ids | stdout | |
| `advisories [--version V] [--crypto-version V] [--repo DIR] [--json] [--osv]` | embedded `advisories.json`; OSV with `--osv` | stdout | the tool's only network call, opt-in |
| `rules` · `version` · `help` | — | stdout | 23 footgun rules; `Version` = `0.1.0` |

## Scripts (`{skill}/scripts/`)

| Script | Does | Env | Reads / writes |
|---|---|---|---|
| `gnark-inventory` | builds the tool once per source hash (`GOWORK=off GOFLAGS=-mod=vendor go build -trimpath`), then `exec`s it | `ZK_AUDIT_BIN` (default `~/.zk-audit/bin`), `ZK_AUDIT_GO` | writes `gnark-inventory-<ver>-<hash>` via a temp file + `mv` |
| `sandbox` | `gnark-inventory sandbox "$@"` | — | — |
| `validate-findings`, `validate-ledger` | `gnark-inventory validate findings\|ledger "$@"` | — | — |
| `assemble` | `gnark-inventory assemble "$@"` | — | — |
| `check-version` | compares `{skill}/VERSION` with the published one; one line only when local is older; always exit 0 | `ZK_AUDIT_NO_UPDATE_CHECK`, `ZK_AUDIT_VERSION_URL` | one HTTPS GET (3 s) |

---

## Developer entry points (not shipped behaviour)

| Entry | Does | Network |
|---|---|---|
| `make check` | `vet`, `test`, `lint-kb`, `standalone`, `eval-score` (CI, with `GOFLAGS=-mod=vendor GOPROXY=off`) | no |
| `make fmt-check` | `gofmt -l` over every tracked Go file but `vendor/` | no |
| `make test-types` | `fixtures` (`go mod download` for the typed fixtures) then typed-mode tests with `ZK_INVENTORY_REQUIRE_TYPES=1` | yes |
| `make cover` | coverage of the tool and the scorer, `coverage/summary.md`, floor `COVER_MIN` (65) | no (after `fixtures`) |
| `make eval-pocs` | `evals/run-pocs` for pool, liveness-roots, sol-gnark-abi, lib-gadgets: sanitized copies, PoCs in the sandbox, offline | fetches modules and solc first |
| `make validate-plugin` | `claude plugin validate .` and `--strict plugins/zk-audit` | no (CLI needed, no API key) |
| `make release-check` (`TAG=…`) | `scripts/release-check`: versions agree, CHANGELOG sections | no |
| `make standalone` | `test/standalone-skill.sh`: skill folder alone in a throwaway `~/.claude/skills` | no |
| `make sync-schemas`, `sync-agents`, `sync-profiles` | copy schemas into the tool, briefs into `plugins/zk-audit/agents/`, regenerate the profile tables | no |
| `make vendor` | `go mod tidy && go mod vendor` | yes |
| `make eval-audit` / `evals/run-audit` | headless audit cases scored with `evals/score` (paid model calls, `--max-budget-usd`) | yes |
| `evals/score run\|summarize\|pilot` | score a run against a key; aggregate; score a pilot against a human's findings | no |
| `evals/pilots/score-pilot` | builds the scorer, runs `score pilot`, prints the `results.md` row | no |
| `evals/sanitize <fixture> <dest>` | copy a fixture outside the repo, strip hint comments, fail if hint text survives | no |
| `test/versions/run` | gnark version support matrix (CI job `versions`) | yes, then offline |
| `test/parity/*.sh` | install / discovery checks in a throwaway `HOME`; `live-*.sh` call `claude -p` and spend money | `live-*` only |
| `.github/workflows/ci.yml` | jobs `check` (gofmt, `make check`, typed tests, coverage, eval PoCs), `plugin` (validate, release check), `versions` ×3 | GitHub |
| `.github/workflows/release.yml` | on a `zk-audit--vX.Y.Z` tag: release check, checks, GitHub release from `CHANGELOG.md` | GitHub |
