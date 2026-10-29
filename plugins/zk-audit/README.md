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
| Agent | `zk-audit:hunter` (`agents/hunter.md`) | Runs one lens bundle and returns FINDING / LEAD blocks. Tools: Read, Grep, Glob. |
| Agent | `zk-audit:critic` (`agents/critic.md`) | Coverage and final-clean critic over the output directory. Tools: Read, Grep, Glob. |
| Agent | `zk-audit:poc-builder` (`agents/poc-builder.md`) | Writes and runs a PoC test in the scratch worktree. |
| Agent | `zk-audit:refuter` (`agents/refuter.md`) | Fresh-context verifier that starts from `refuted: true`. |
| Tool | `skills/zk-audit/tools/gnark-inventory` | Deterministic detect / inventory / bundle / validate / assemble / lint-kb. |

The skill folder `skills/zk-audit/` is self-contained: it holds the tool, its
wrapper scripts, the JSON schemas and a copy of each agent file
(`skills/zk-audit/agents/`, the canonical copy; `make sync-agents` copies it
to `agents/`). Copied alone into `~/.claude/skills/zk-audit` it runs the same
audit; the commands become `/zk-audit setup|recon|diff` and the four agents run
as general-purpose agents briefed with their file. Only the plugin install
enforces the agents' `tools:` allowlists (hunter, critic and refuter: Read,
Grep, Glob; a docs test fails if one lists a write-capable tool); a
standalone install restricts them by prompt only.

## gnark-inventory

A Go module (Go ≥ 1.24, dependency `golang.org/x/tools`, vendored). Run it
through `skills/zk-audit/scripts/gnark-inventory`, which builds it once into
`~/.zk-audit/bin/` and then executes it.

| Subcommand | Output |
|---|---|
| `args [--repo DIR] [--mode M] [--run-id ID] [--home DIR] -- WORDS...` | Parses a `/zk-audit ...` invocation (mode, profile, scope files, `--local`, `--loop N`, `--no-poc`, `--file-output`, `--out DIR`, `--profile P`, setup's `--check-only`) into JSON with defaults (output `~/.zk-audit/<repo>/<run-id>`, passes from the profile); exit 1 lists every invalid word. |
| `detect --repo DIR [--out stack.json]` | gnark / gnark-crypto versions, matching advisories, backends, curves, Solidity / Foundry / Hardhat / Circom / Noir presence. |
| `inventory --repo DIR --out DIR [--files a,b] [--syntax-only] [--allow-network] [--sandbox auto\|on\|off]` | `inventory.json`, `inventory.md`, `binding-table.md`, `coverage-ledger.json` (seeded), `stack.json`. |
| `bundle --out DIR --skill SKILL_DIR [--profile P]` | One `bundles/<agent>.md` per selected agent: source shard (paths and line counts), binding table, inventory items, SOP, lens, shared rules. |
| `profiles [--profile P] [--markdown] [--check-docs SKILL_DIR] [--sync-docs SKILL_DIR]` | Prints the lens, critic and profile definitions (the embedded `profiles.json`, the single source of truth), one profile with its lenses, or the generated Markdown tables; `--check-docs` / `--sync-docs` compare or rewrite the tables in `SKILL.md` and `references/orchestration.md`. |
| `validate findings FILE [--out DIR]` | Checks `findings.json` against `skills/zk-audit/schemas/findings.schema.json` plus semantic rules. |
| `validate ledger FILE [--out DIR]` | Checks `coverage-ledger.json` against `skills/zk-audit/schemas/ledger.schema.json` plus semantic rules. |
| `validate stack FILE` | Checks `stack.json` against `skills/zk-audit/schemas/stack.schema.json`. |
| `assemble --out DIR [--findings F] [--ledger F] [--stack F] [--inventory F] [--repo DIR] [--report F] [--file-output]` | Validates `findings.json` and `coverage-ledger.json` (and `stack.json`), refuses invalid input and forbidden clean claims (exit 1, no report), and renders `REPORT.md` with code quoted from `--repo` and coverage counted only from the ledger. |
| `sandbox [--rw DIR]... [--ro DIR]... [--cwd DIR] [--timeout SEC] [--mem MB] [--allow-network] [--gocache DIR] [--goflags F] [--env NAME]... [--engine auto\|bwrap\|sandbox-exec\|none] [--require] [--check] -- CMD [ARGS...]` | Runs a command on untrusted code (PoC `go test` / `forge test`, the inventory's type loading) in the OS sandbox and returns its status (124 time limit, 125 setup failure, 127 not found). `--check` prints the engine. |
| `diff --repo DIR --base REV [--head REV] [--out DIR]` | Lists the files changed between the merge base of `--base` and `--head`, and `--head`, and flags the high-risk triggers of diff mode (removed or newly conditional constraints, removed range checks, changed public inputs, new hints, gnark version changes, changed verifier contracts, VK files and verifier call sites) from git objects only; JSON, or `diff.json` + `diff.md` with `--out`. |
| `ledger mark --out DIR (--unit ID\|--match S\|--lens L\|--kind K\|--class C\|--from STATUS)... [--status S] [--agent A]... [--reviewed P]... [--fingerprint F]... [--reason R] [--notes T] [--wave N]` | Changes the selected ledger units in place (status, agents, reviewed paths, fingerprints, reason), validates the result with the output-directory checks and writes it atomically, or writes nothing (exit 1). |
| `ledger add --out DIR --kind K --subject S --class C --lens L [--path FILE:LINE] [--notes T]` · `ledger show --out DIR` | Adds a unit the seeder missed (a critic's finding); prints status counts and units. |
| `agents save --out DIR --id ID [--from FILE] [--status done\|blocked\|failed\|refused] [--reason R]` · `agents list --out DIR` | Saves an agent's raw return to `<out>/agents/<ID>.md` and its status, FINDING / LEAD counts and attempts to `agents/index.json`; a stopped or refused agent needs a reason. |
| `lint-kb [--gnark-src DIR] SKILL_DIR` | Lints the knowledge base: every vector has D/FP/Source/Seed/PoC, sources are real URLs on allowed hosts or `gnark/<path>` references (checked against a gnark checkout with `--gnark-src`), seeds name real detector rules, PoCs name real templates, ids are unique, slice counts match the index, and the advisory table matches the tool. |
| `rules` | Prints the footgun detector rules as JSON. |
| `advisories [--version vX.Y.Z]` | Prints the embedded advisory table, or only the advisories that affect a version. |
| `version` | Prints the tool version. |

Every validator fails when it inspects zero items.

**Writes.** `detect --out`, `inventory --out`, `bundle` and `assemble --out` /
`--report` refuse (exit 2) a path inside the audited repository, after
resolving symlinks; `assemble --file-output` is the one way to put a file
there (the report copy). Quotes in `REPORT.md` resolve symlinks and are
refused when the real file leaves the repository.

**Network.** By default the tool sets `GOPROXY=off` when it calls the go
command, so an audit never downloads modules. `--allow-network` lifts that for
type loading (for example when the target's dependencies are not in the module
cache yet).

**Sandbox.** Commands that execute target code run under
`scripts/sandbox`. Linux: bubblewrap with its own network namespace (no
network), the root file system read-only, `--rw` directories writable, the
home directory and `/tmp` replaced by empty tmpfs (the module cache, Go root,
Foundry and svm directories re-bound read-only), new PID/IPC/UTS namespaces,
capabilities dropped when run as root. macOS: `sandbox-exec` with network and
writes outside `--rw` and the temporary directories denied (reads are not
restricted; untested in CI). Everywhere: a scrubbed environment (tokens and
credentials dropped), `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOFLAGS=-mod=mod`, `GOPROXY=off`, a separate build cache
(`~/.zk-audit/gocache`), an address-space limit per process (`--mem`, default
8192 MiB) and a time limit (`--timeout`, default 600 s). With neither engine
it warns and applies only those limits. `inventory` reruns itself inside the
sandbox for type loading (`--sandbox auto`, the default).

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
| `scripts/sandbox` | `gnark-inventory sandbox "$@"` |
