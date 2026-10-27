# zk-audit

A Claude Code plugin that audits zero-knowledge systems built with
[gnark](https://github.com/Consensys/gnark): the circuits, and the verifier
contracts, protocol state and prover services that trust their proofs.

It looks for soundness, completeness and privacy bugs in circuits (hints, range
checks, field wraparound, emulated arithmetic, std gadgets, commitments,
recursion) and for bugs at the seams (public-input binding, nullifiers and
replay, VK drift, proof malleability). It proves what it can with a witness or a
Go / Foundry test, and it records what it actually examined.

> Status: early. The inventory tool, schemas, validators and knowledge base
> work today; the agent orchestration is a skeleton (see `PLAN.md` §9).

## Install

```text
/plugin marketplace add shramee/zk-audit
/plugin install zk-audit@zk-audit
```

Requirements: Go ≥ 1.24 for the bundled `gnark-inventory` tool. Optional:
`forge` (Foundry) for contract PoCs, and the companion skills listed by
`/zk-audit:setup`.

## Use

| Command | What it does |
|---|---|
| `/zk-audit` | Detects the stack and runs the **standard** profile on the repo. |
| `/zk-audit quick` · `deep` | Picks a profile. |
| `/zk-audit circuits/transfer.go contracts/Pool.sol` | Limits scope to the named files. |
| `/zk-audit diff origin/main` or `/zk-audit:diff origin/main` | Reviews a commit range. |
| `/zk-audit recon` or `/zk-audit:recon` | Recon only: stack, advisories, public-input table, hint and footgun inventory. |
| `/zk-audit:setup` | Shows companions and tools; installs only after you confirm. |

Flags: `--local`, `--loop N`, `--no-poc`, `--file-output`, `--out DIR`.

When the plugin namespaces skills, the main entry point is `/zk-audit:zk-audit`.
Asking a plain question ("is this circuit ok?") gets a direct answer without
spawning agents.

Output goes to `~/.zk-audit/<repo>/<run-id>/` (`REPORT.md`, `findings.json`,
`coverage-ledger.json`, `binding-table.md`, `system-map.md`, `pocs/`). Nothing
is written into your repository unless you pass `--file-output`. PoCs run in a
scratch git worktree.

### The inventory tool on its own

```bash
plugins/zk-audit/scripts/gnark-inventory detect --repo /path/to/repo
plugins/zk-audit/scripts/gnark-inventory inventory --repo /path/to/repo --out /tmp/inv
plugins/zk-audit/scripts/gnark-inventory validate findings /tmp/inv/findings.json
```

See `plugins/zk-audit/README.md` for every subcommand.

## Repository layout

```text
.claude-plugin/marketplace.json     marketplace "zk-audit"
plugins/zk-audit/
  .claude-plugin/plugin.json
  skills/zk-audit/SKILL.md          entry point: modes, profiles, phases
  skills/zk-audit/references/       knowledge base, lenses, judging, report format
  commands/                         /zk-audit:setup, /zk-audit:recon, /zk-audit:diff
  agents/                           agent definitions (poc-builder, refuter)
  tools/gnark-inventory/            Go tool: detect, inventory, validate, lint-kb
  scripts/                          thin wrappers around the tool
  schemas/                          findings, ledger and stack JSON schemas
docs/                               research notes and design notes
PLAN.md                             the design
```

## Development

```bash
make check     # go vet, go test, JSON parse, knowledge-base lint
```

## License

Not licensed yet. Parts are adapted from MIT-licensed work by zkSecurity,
pashov / AI Skills Contributors and Cloudflare; see `NOTICE`.
