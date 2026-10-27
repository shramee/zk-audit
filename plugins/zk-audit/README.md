# zk-audit plugin

Audits gnark circuits and the code that consumes their proofs.

## Components

| Kind | Name | Purpose |
|---|---|---|
| Skill | `zk-audit` (`skills/zk-audit/SKILL.md`) | Entry point. Guidance mode for questions, full-audit mode for audits. |
| Command | `/zk-audit:setup` | Shows companions and tools, installs only after consent. |
| Command | `/zk-audit:recon` | Phase 0 and Phase 1 only. |
| Command | `/zk-audit:diff` | Reviews a commit range with high-risk triggers. |
| Agent | `zk-audit:poc-builder` (`agents/poc-builder.md`) | Writes and runs a PoC test in the scratch worktree. |
| Agent | `zk-audit:refuter` (`agents/refuter.md`) | Fresh-context verifier that starts from `refuted: true`. |
| Tool | `tools/gnark-inventory` | Deterministic detect / inventory / validate / lint-kb. |

## gnark-inventory

A Go module (Go ≥ 1.24, dependency `golang.org/x/tools`, vendored). Run it
through `scripts/gnark-inventory`, which builds it once into
`~/.zk-audit/bin/` and then executes it.

| Subcommand | Output |
|---|---|
| `detect --repo DIR [--out stack.json]` | gnark / gnark-crypto versions, matching advisories, backends, curves, Solidity / Foundry / Hardhat / Circom / Noir presence. |
| `inventory --repo DIR --out DIR [--files a,b] [--syntax-only]` | `inventory.json`, `inventory.md`, `binding-table.md`, `coverage-ledger.json` (seeded). |
| `validate findings FILE` | Checks `findings.json` against `schemas/findings.schema.json` plus semantic rules. |
| `validate ledger FILE` | Checks `coverage-ledger.json` against `schemas/ledger.schema.json` plus semantic rules. |
| `validate stack FILE` | Checks `stack.json` against `schemas/stack.schema.json`. |
| `lint-kb DIR` | Lints the knowledge base: every vector has a real `Source:`, ids are unique, the advisory table matches the tool. |
| `advisories [--version vX.Y.Z]` | Prints the embedded advisory table, or only the advisories that affect a version. |
| `version` | Prints the tool version. |

Every validator fails when it inspects zero items.

**Loading.** `inventory` loads packages with `golang.org/x/tools/go/packages`
and full type information, which gives exact public-witness order including
types from other packages and constant array lengths. If loading fails (for
example, dependencies not downloaded) it falls back to `go/parser` only and
marks every result it could not resolve. `--syntax-only` forces the fallback.

## Scripts

| Script | Does |
|---|---|
| `scripts/gnark-inventory` | Builds (once) and runs the tool. |
| `scripts/validate-findings` | `gnark-inventory validate findings "$@"` |
| `scripts/validate-ledger` | `gnark-inventory validate ledger "$@"` |
