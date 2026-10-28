# zk-audit plugin

Audits gnark circuits and the code that consumes their proofs.

```text
/plugin marketplace add shramee/zk-audit
/plugin install zk-audit@zk-audit
```

Or copy `skills/zk-audit/` alone into `~/.claude/skills/zk-audit` (see the
repository README).

## Components

| Kind | Name | Purpose |
|---|---|---|
| Skill | `zk-audit` (`skills/zk-audit/SKILL.md`) | Entry point. Guidance mode for questions, full-audit mode for audits. |
| Command | `/zk-audit:setup` | Shows companions and tools, installs only after consent (`references/modes/setup.md`). |
| Command | `/zk-audit:recon` | Phase 0 and Phase 1 only (`references/modes/recon.md`). |
| Command | `/zk-audit:diff` | Reviews a commit range with high-risk triggers (`references/modes/diff.md`). |
| Agent | `zk-audit:poc-builder` (`agents/poc-builder.md`) | Writes and runs a PoC test in the scratch worktree. |
| Agent | `zk-audit:refuter` (`agents/refuter.md`) | Fresh-context verifier that starts from `refuted: true`. |
| Tool | `skills/zk-audit/tools/gnark-inventory` | Deterministic detect / inventory / bundle / validate / assemble / lint-kb. |

The skill folder `skills/zk-audit/` is self-contained: it holds the tool, its
wrapper scripts, the JSON schemas and a copy of each agent file
(`skills/zk-audit/agents/`, the canonical copy; `make sync-agents` copies it
to `agents/`). Copied alone into `~/.claude/skills/zk-audit` it runs the same
audit; the commands become `/zk-audit setup|recon|diff` and the two agents run
as general-purpose agents briefed with their file.

## gnark-inventory

A Go module (Go ≥ 1.24, dependency `golang.org/x/tools`, vendored). Run it
through `skills/zk-audit/scripts/gnark-inventory`, which builds it once into
`~/.zk-audit/bin/` and then executes it.

| Subcommand | Output |
|---|---|
| `detect --repo DIR [--out stack.json]` | gnark / gnark-crypto versions, matching advisories, backends, curves, Solidity / Foundry / Hardhat / Circom / Noir presence. |
| `inventory --repo DIR --out DIR [--files a,b] [--syntax-only] [--allow-network]` | `inventory.json`, `inventory.md`, `binding-table.md`, `coverage-ledger.json` (seeded), `stack.json`. |
| `bundle --out DIR --skill SKILL_DIR [--profile P]` | One `bundles/<agent>.md` per selected agent: source shard (paths and line counts), binding table, inventory items, SOP, lens, shared rules. |
| `validate findings FILE` | Checks `findings.json` against `skills/zk-audit/schemas/findings.schema.json` plus semantic rules. |
| `validate ledger FILE` | Checks `coverage-ledger.json` against `skills/zk-audit/schemas/ledger.schema.json` plus semantic rules. |
| `validate stack FILE` | Checks `stack.json` against `skills/zk-audit/schemas/stack.schema.json`. |
| `assemble --out DIR [--findings F] [--ledger F] [--stack F] [--inventory F] [--repo DIR] [--report F]` | Validates `findings.json` and `coverage-ledger.json` (and `stack.json`), refuses invalid input and forbidden clean claims (exit 1, no report), and renders `REPORT.md` with code quoted from `--repo` and coverage counted only from the ledger. |
| `lint-kb [--gnark-src DIR] SKILL_DIR` | Lints the knowledge base: every vector has D/FP/Source/Seed/PoC, sources are real URLs on allowed hosts or `gnark/<path>` references (checked against a gnark checkout with `--gnark-src`), seeds name real detector rules, PoCs name real templates, ids are unique, slice counts match the index, and the advisory table matches the tool. |
| `rules` | Prints the footgun detector rules as JSON. |
| `advisories [--version vX.Y.Z]` | Prints the embedded advisory table, or only the advisories that affect a version. |
| `version` | Prints the tool version. |

Every validator fails when it inspects zero items.

**Network.** By default the tool sets `GOPROXY=off` when it calls the go
command, so an audit never downloads modules. `--allow-network` lifts that for
type loading (for example when the target's dependencies are not in the module
cache yet).

**Loading.** `inventory` loads packages with `golang.org/x/tools/go/packages`
and full type information, which gives exact public-witness order including
types from other packages and constant array lengths. If loading fails (for
example, dependencies not downloaded) it falls back to `go/parser` only and
marks every result it could not resolve. `--syntax-only` forces the fallback.

## Scripts

All under `skills/zk-audit/`:

| Script | Does |
|---|---|
| `scripts/gnark-inventory` | Builds (once) and runs the tool. |
| `scripts/validate-findings` | `gnark-inventory validate findings "$@"` |
| `scripts/validate-ledger` | `gnark-inventory validate ledger "$@"` |
| `scripts/assemble` | `gnark-inventory assemble "$@"` |
