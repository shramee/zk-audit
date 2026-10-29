# zk-audit

A Claude Code plugin that audits zero-knowledge systems built with
[gnark](https://github.com/Consensys/gnark): the circuits, and the verifier
contracts, protocol state and prover services that trust their proofs.

It looks for soundness, completeness and privacy bugs in circuits (hints, range
checks, field wraparound, emulated arithmetic, std gadgets, commitments,
recursion) and for bugs at the seams (public-input binding, nullifiers and
replay, VK drift, proof malleability). It proves what it can with a witness or a
Go / Foundry test, and it records what it actually examined.

> Status: early. The inventory tool, schemas, validators, report assembler and
> knowledge base work today; the agent orchestration has recorded blind
> end-to-end runs (quick, standard and deep on the pool fixture, 2026-10-29). See
> [Current status](#current-status) and the project x-ray in
> [`docs/x-ray/`](docs/x-ray/x-ray.md).

## Review scope

### What gets reviewed

| Artifact | What the audit reads |
|---|---|
| gnark circuits | Every `Define` method, the custom gadgets and helpers it calls, hint functions and their `RegisterHint` / `NewHint` sites. |
| Witness layout | The witness struct and its `gnark:",public"` fields in public-witness order, including how slices and arrays flatten. |
| Use of gnark std | How std gadgets are called, and whether the caller meets each gadget's preconditions ([`gnark-api-footguns.md`](plugins/zk-audit/skills/zk-audit/references/gnark-api-footguns.md)). |
| Off-circuit Go | Witness assignment, the prover service, proving and verifying key loading, deserialisation of keys, proofs and witnesses, setup code, prover and verifier options, logging. |
| Solidity | The verifier contract (gnark-generated or custom) and the contracts that consume proofs: how public inputs are built, nullifier and root state, and who can change the verifier or VK (setters, proxies, upgrades). |
| Dependencies | gnark and gnark-crypto versions in every `go.mod`, matched against the embedded advisory table ([`gnark-versions.md`](plugins/zk-audit/skills/zk-audit/references/gnark-versions.md)). |

gnark std internals, gnark-crypto, the gnark backends and vendored libraries
are **peripheral**. Agent bundles list them but do not inline them, and they
are checked only against known advisories and each gadget's documented
contract at the pinned version.

Other frontends: `.circom` files go to zkSecurity's `circom-auditor` if it is
installed, otherwise they get a reduced pass with the generic vectors in
[`generic-zk.md`](plugins/zk-audit/skills/zk-audit/references/attack-vectors/generic-zk.md).
Noir is detected and reported as out of scope. If the repository has neither
gnark nor a verifier contract, the skill says it does not fit and stops. See
[`companions.md`](plugins/zk-audit/skills/zk-audit/references/companions.md).

### What must be covered

Properties the audit checks:

| Property | Question | Lenses | Vectors |
|---|---|---|---|
| Soundness | Can a prover make a false statement verify (an under-constrained value)? | C1–C5, G1, G3 | V-H, V-R, V-F, V-S, V-M, V-E, V-CM, V-G |
| Completeness | Can every honest user always get a proof (no over-constraint, zero divisor, prover DoS)? | C6, C3, I4 | V-F2, V-M7, V-PV2, V-PV3 |
| Zero knowledge / privacy | Do the proof, its public inputs or the service leak a secret? | C5, I4, F1 | V-CM2, V-G6, V-PV5 |
| Statement binding and replay | Is the proof bound to what the contract does with it: input order and encoding, sender, recipient, chain, nonce, nullifier? | I1, I3, G2 | V-PI, V-PS, V-CM5 |
| Setup and key trust | Do the keys come from a trusted setup, and is the deployed verifier and VK the one for this circuit? | I2, I4 | V-PV1, V-VC, V-CM4 |
| Known advisories | Is the pinned gnark version affected? | Phase 0, I4 | `gnark-versions.md` |

Privacy has no dedicated lens or ledger class yet; it relies on the vectors
above and the first-principles lens.

Coverage checklist (lens files are in
[`references/agents/`](plugins/zk-audit/skills/zk-audit/references/agents/),
slices in [`references/attack-vectors/`](plugins/zk-audit/skills/zk-audit/references/attack-vectors/index.md)):

| Area | Lens | Vector slice | Profiles |
|---|---|---|---|
| Hint outputs and prover-chosen values | C1 hint soundness | `hints.md` (V-H) | all |
| Bit decomposition, range checks, comparisons | C2 range and decomposition | `range-bits.md` (V-R) | standard, deep |
| Native and emulated field arithmetic | C3 field arithmetic | `field-arith.md` (V-F) | standard, deep |
| Go control flow, selectors, gated checks | C4 control and selectors | `selector-control.md` (V-S) | standard, deep |
| Hashes, Merkle proofs, signatures, curves | C5 crypto gadgets | `hash-merkle.md` (V-M), `curves-signatures.md` (V-E) | standard, deep |
| Commitments, recursion, Fiat-Shamir | C5 crypto gadgets | `commitments-recursion.md` (V-CM) | standard, deep |
| Circuit vs spec, invariants, over-constraint | C6 spec and invariants | `generic-zk.md` (V-G) | standard, deep |
| Public-input order, encoding, binding | I1 public-input binding | `public-inputs.md` (V-PI) | all |
| Verifier contract, VK provenance, admin swap | I2 verifier contracts | `verifier-contracts.md` (V-VC) | standard, deep |
| Nullifiers, roots, replay, identities | I3 protocol state | `protocol-state.md` (V-PS) | standard, deep |
| Setup, keys, deserialisation, logs, versions | I4 prover service | `prover-service.md` (V-PV) | standard, deep |
| Circuit × contract × state seams | G2 binding gaps | — | all |
| Range × field × invariant seams | G1 numerical gaps | — | deep |
| Gadget preconditions broken by the caller's wiring | G3 composition gaps | — | deep |
| Hint ↔ constraint, native Go ↔ circuit, off-chain ↔ in-circuit hash, Groth16 ↔ PLONK, encode ↔ decode | A1 asymmetry | — | deep |
| Every other assumption (liveness, griefing, upgrades, cross-circuit reuse) | F1 first principles | — | standard, deep |

Every slice also gets its own vector-scan shard (V-hints, V-range, …,
V-prover) in every profile. The coverage ledger records one unit per circuit ×
lens class, public input, hint, verifier, contract function × integration
class, prover file and gnark dependency; the report states which units were
covered, deferred or not applicable, and never says "verified clean".

### Out of scope

- gnark backends, gnark-crypto and gnark std internals, beyond known
  advisories.
- Solidity bugs unrelated to proof consumption (token accounting, general
  access control, gas). The integration lenses cover the ZK surface only; the
  `solidity-auditor` companion extends this when installed, and the report
  says which applied.
- Economic and game-theoretic design. F1 may raise leads, but there is no
  systematic review.
- Infrastructure: servers, key storage, CI, deployment pipelines, front ends.
- Formal verification, Noir, Halo2 and other frontends.

Some facts cannot be decided from source. Findings that depend on them are
marked `needs_validation` with the blocker named: which verifier and VK are
deployed and at which address, whether the setup ceremony was honest and where
the keys came from, which gnark version runs in production, and how trusted
parties (admin, relayer, sequencer) behave.

### What the auditee should provide

- **`zk-audit.md`** at the repository root (optional; `/zk-audit recon` can
  draft it): scope, trusted parties (setup ceremony, admin, relayer, sequencer,
  designated prover), the properties that must hold ("each note is spent
  once"), accepted risks, and prior findings or audits. It explains intent; it
  never excuses a missing constraint.
- The spec or paper the circuit implements. C6 checks the circuit against it;
  without one, the statement is derived from the contract.
- Deployed addresses and chains, which verifier contract and VK are live, and
  the gnark version and options that generated them.
- How the proving and verifying keys were produced (ceremony transcript or
  setup procedure).
- The gnark version in production, if it differs from `go.mod`.
- Dependencies in the module cache or `vendor/`, so the inventory can load
  types offline.

### Current status

| Part | State |
|---|---|
| `gnark-inventory`: `args`, `detect`, `inventory`, `bundle`, `profiles`, `validate`, `assemble`, `ledger`, `agents`, `memory`, `diff`, `sandbox`, `lint-kb`, `advisories`, `rules` | Implemented, unit tested, run in CI. |
| Safety by code | Hunters and critics are read-only plugin agent types (Read, Grep, Glob); PoCs and recon type loading run in an OS sandbox (bubblewrap on Linux: no network, writes only to the worktree; `sandbox-exec` on macOS, untested in CI); the tool refuses writes into the target and symlinked quotes; `validate` / `assemble` check PoC files and agent outputs on disk. A standalone skill install restricts agent tools by prompt only. |
| Findings, ledger and stack schemas with validators | Implemented. |
| Deterministic report assembler (`assemble`) | Implemented: validates its inputs, refuses forbidden clean claims, quotes code from the audited tree, counts coverage only from the ledger; golden tests. |
| Knowledge base: 79 sourced vectors in 12 slices, advisory table, API footguns, judging, PoC templates | Written and linted. Four PoC templates were run against gnark v0.14.0. |
| Skill, orchestration, lens files, commands, `hunter`, `critic`, `poc-builder` and `refuter` agents | Written as prompts. One blind end-to-end run is recorded: quick profile on the pool fixture, recall 12 of 14 planted items, no false positives ([`evals/baseline/pool-quick.md`](plugins/zk-audit/evals/baseline/pool-quick.md)). |
| Install routes | Claude Code plugin, or the skill folder copied alone into `~/.claude/skills/zk-audit`; both checked in [`docs/pashov-parity.md`](docs/pashov-parity.md), the second on every CI run. |
| Eval harness | One fixture (`pool`) with an answer key, a sanitizer that strips hint comments, and executed eval PoCs in CI. No scored LLM runs in CI, no all-safe panel, no `case.yaml` suite yet. |
| `diff` mode, `--loop` memory | Tool support: `diff` flags the high-risk triggers, `memory` holds NEW / KNOWN tags, "seen in k/N" and the stop rule. Not yet measured in an end-to-end run. |
| Coverage critics | Prompted (`zk-audit:critic`); the ledger records a decision per missing unit through `ledger add` / `ledger mark`. |
| Regenerate-and-diff of `Verifier.sol` (deep profile) | Not automated. |
| Semgrep rules, zkao bridge | Not started. |

## Install

Two routes give the same audit. The skill folder
`plugins/zk-audit/skills/zk-audit/` is self-contained (tool, scripts, schemas,
agent briefs, `VERSION`), so it also works copied on its own.

**Ask your agent** (any runtime that loads `~/.claude/skills`, the way
[pashov/skills](https://github.com/pashov/skills) installs):

```text
Install https://github.com/shramee/zk-audit and run zk-audit on this repo
Install https://github.com/shramee/zk-audit and run zk-audit recon on this repo
update zk-audit to the latest version
```

What the agent should do for "install" and "update" (one copy, nothing else
changes):

```bash
tmp="$(mktemp -d)" && git clone --depth 1 https://github.com/shramee/zk-audit "$tmp/zk-audit"
mkdir -p ~/.claude/skills && rm -rf ~/.claude/skills/zk-audit
cp -R "$tmp/zk-audit/plugins/zk-audit/skills/zk-audit" ~/.claude/skills/zk-audit
```

If the skill list does not show `zk-audit` yet in the running session, read
`~/.claude/skills/zk-audit/SKILL.md` and follow it. In this route the modes
are `/zk-audit setup|recon|diff`, and the hunters, critics, PoC builder and
refuter run as general-purpose agents briefed with `agents/*.md` from the
skill folder (read-only by prompt only).

**Claude Code plugin** (adds the `/zk-audit:setup|recon|diff` commands and the
`zk-audit:hunter`, `zk-audit:critic`, `zk-audit:poc-builder` and
`zk-audit:refuter` agent types; hunter, critic and refuter have read-only
tool allowlists, which only a plugin install enforces):

```text
/plugin marketplace add shramee/zk-audit
/plugin install zk-audit@zk-audit
```

Update with `/plugin marketplace update zk-audit` then
`/plugin update zk-audit@zk-audit`.

Each full audit starts with a non-blocking update check
(`scripts/check-version`): one request for the published `VERSION` file,
nothing about your code is sent, and it prints a line only when a newer
version exists. `ZK_AUDIT_NO_UPDATE_CHECK=1` turns it off.

Requirements: Go ≥ 1.24 for the bundled `gnark-inventory` tool (it builds
offline from vendored sources). Optional: `forge` (Foundry) for contract
PoCs, and the companion skills listed by `/zk-audit setup`.

## Use

| Command | What it does |
|---|---|
| `/zk-audit` | Detects the stack and runs the **standard** profile on the repo. |
| `/zk-audit quick` · `deep` | Picks a profile. |
| `/zk-audit circuits/transfer.go contracts/Pool.sol` | Limits scope to the named files. |
| `/zk-audit diff origin/main` or `/zk-audit:diff origin/main` | Reviews a commit range. |
| `/zk-audit recon` or `/zk-audit:recon` | Recon only: stack, advisories, public-input table, hint and footgun inventory. |
| `/zk-audit setup` or `/zk-audit:setup` | Shows companions and tools; installs only after you confirm. |

Flags: `--local`, `--loop N`, `--no-poc`, `--file-output`, `--out DIR`,
`--profile P`. The skill parses them with `gnark-inventory args`.

When the plugin namespaces skills, the main entry point is `/zk-audit:zk-audit`.
Asking a plain question ("is this circuit ok?") gets a direct answer without
spawning agents.

Output goes to `~/.zk-audit/<repo>/<run-id>/` (`REPORT.md`, `findings.json`,
`coverage-ledger.json`, `binding-table.md`, `system-map.md`, `pocs/`). Nothing
is written into your repository unless you pass `--file-output`. PoCs run in a
scratch git worktree.

### The inventory tool on its own

```bash
plugins/zk-audit/skills/zk-audit/scripts/gnark-inventory detect --repo /path/to/repo
plugins/zk-audit/skills/zk-audit/scripts/gnark-inventory inventory --repo /path/to/repo --out /tmp/inv
plugins/zk-audit/skills/zk-audit/scripts/gnark-inventory validate findings /tmp/inv/findings.json
```

See `plugins/zk-audit/README.md` for every subcommand.

## Repository layout

```text
.claude-plugin/marketplace.json     marketplace "zk-audit"
plugins/zk-audit/
  .claude-plugin/plugin.json
  skills/zk-audit/                  self-contained skill folder (works copied alone)
    SKILL.md                        entry point: modes, profiles, phases
    references/                     knowledge base, lenses, judging, report format, modes/
    agents/                         poc-builder and refuter briefs (canonical copy)
    tools/gnark-inventory/          Go tool: detect, inventory, bundle, validate, assemble, lint-kb
    scripts/                        thin wrappers around the tool
    schemas/                        findings, ledger and stack JSON schemas
  commands/                         /zk-audit:setup, /zk-audit:recon, /zk-audit:diff (thin wrappers)
  agents/                           plugin agent definitions (copies of skills/zk-audit/agents/)
evals/                              eval answer keys, PoCs and the sanitizer (not installed)
testdata/                           tool test fixtures and golden reports (not installed)
docs/                               research notes and design notes
PLAN.md                             the design
```

## Development

```bash
make check     # go vet, go test, JSON parse, knowledge-base lint
```

## License

Unlicensed for now; the license decision is deferred and there is no
`LICENSE` file. Parts are adapted from MIT-licensed work by zkSecurity,
pashov / AI Skills Contributors and Cloudflare; see `NOTICE`.
