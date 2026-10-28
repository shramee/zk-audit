# Orchestration (delegated mode)

<!-- Turn structure, bounded worker pool and progress console adapted from zkSecurity zk-skills circom-auditor orchestration/claude.md (MIT, (c) 2026 zkSecurity); profiles and critic waves from Cloudflare security-audit-skill (MIT, (c) 2025-2026 Cloudflare, Inc.). -->

Use this when the runtime can spawn subagents (Claude Code `Agent`). With
`--local`, or without subagents, run the same lenses one after another in this
context and skip the progress console.

Write the prompts in plain, runtime-neutral language. Never ask an agent to
install, write into the target repo, or use the network.

## Agents

| Id | Lens file | Group | Shard |
|---|---|---|---|
| C1 | `agents/C1-hint-soundness.md` | circuit | circuit |
| C2 | `agents/C2-range-decomposition.md` | circuit | circuit |
| C3 | `agents/C3-field-arithmetic.md` | circuit | circuit |
| C4 | `agents/C4-control-selector.md` | circuit | circuit |
| C5 | `agents/C5-crypto-gadgets.md` | circuit | circuit |
| C6 | `agents/C6-spec-invariant.md` | circuit | all |
| I1 | `agents/I1-public-input-binding.md` | integration | integration |
| I2 | `agents/I2-verifier-contract.md` | integration | integration |
| I3 | `agents/I3-protocol-state.md` | integration | integration |
| I4 | `agents/I4-prover-service.md` | integration | prover |
| V-hints, V-range, V-field, V-selector, V-hash, V-curves, V-commit, V-generic | `agents/vector-scan.md` + one circuit slice each | vector scan | circuit |
| V-pubin, V-verifier, V-state, V-prover | `agents/vector-scan.md` + one integration slice each | vector scan | integration (V-prover: prover) |
| G1 | `agents/G1-numerical-gap.md` | gap | circuit |
| G2 | `agents/G2-binding-gap.md` | gap | all |
| G3 | `agents/G3-composition-gap.md` | gap | circuit |
| A1 | `agents/A1-asymmetry.md` | cross | all |
| F1 | `agents/F1-first-principles.md` | cross | all |

Profiles (from `SKILL.md`): **quick** = V-* shards + C1 + I1 + G2. **standard** =
C1–C6, I1–I4, V-*, G2, F1. **deep** = all of the above plus G1, G3, A1, repeated
for 3 passes with memory. Skip agents whose shard is empty (for example no
Solidity means no I1–I3 or integration V-shards); mark them `Skipped` with the
reason, and record their ledger units as `not_applicable`.

## Turn 1 — Discover

Print the banner from `SKILL.md`. In parallel:

1. Resolve `{skill}` (`SKILL.md`, first paragraph).
2. Create the output directory `~/.zk-audit/<repo>/<run-id>/` (or `--out`).
3. Run Phase 0: `{skill}/scripts/gnark-inventory detect --repo <repo> --out <out>/stack.json`.
4. Detect companions (`companions.md`).

Print the stack line and the companion line. Ask the single profile/model
question (`AskUserQuestion`), or state the default.

## Turn 2 — Recon

1. `{skill}/scripts/gnark-inventory inventory --repo <repo> --out <out> [--files …]`.
   If the load mode is not `types`, say so; offer `--allow-network` (it lets the
   go command download modules) only with the user's consent.
2. Read `inventory.md`, every `Define`, and the contracts that call verifiers.
3. Complete `binding-table.md` and write `system-map.md` (see `SKILL.md`
   Phase 1).
4. Validate the ledger: `gnark-inventory validate ledger <out>/coverage-ledger.json`.
5. For `/zk-audit recon`, stop here (`commands/recon.md` lists the output).

## Turn 3 — Build bundles

```bash
{skill}/scripts/gnark-inventory bundle --out <out> --skill {skill} --profile <profile>
```

This writes `<out>/bundles/<agent-id>.md` for every selected agent and prints a
table of bundle paths and line counts. A bundle lists its **source shard** as
paths with line counts (not inlined), inlines `binding-table.md`, the
inventory items for those files, `senior-auditor-sop.md`, the lens file (and
the vector slice for V-shards) and `shared-rules.md`.

Shards:

- **circuit**: Go files in packages that define a production circuit, plus Go
  files with hint sites or footgun hits they use. With more than two circuits
  the tool writes one circuit shard per circuit package, and circuit lenses get
  one bundle per shard (`C1@<package>`).
- **integration**: the Solidity files in scope plus the circuit files that
  declare public inputs.
- **prover**: Go files outside circuit packages that import gnark backends,
  witness or Solidity export.
- **all**: the union.

Peripheral files (gnark std at the pinned version in the module cache,
vendored libraries) are listed by directory, never inlined.

## Turn 4 — Hunt (bounded pool, at most 6 running)

Before spawning, print the console. Mark the first six `Running`, the rest
`Queued`, omitted agents `Skipped`:

```markdown
## Agent Progress

| Agent | Lens | Shard | Status | Result |
|---|---|---|---|---|
| V-hints | vector scan: hints | circuit | Running | – |
| C1 | hint soundness | circuit | Running | – |
| I1 | public-input binding | integration | Running | – |
| G2 | binding gaps | all | Queued | – |
```

Spawn at most six agents at once. When one returns, mark it `Done` with a
count (`2 findings, 1 lead`), or `Blocked` with the reason, then start the
next queued agent. Print the updated table after each batch. If the runtime
returns parallel results only per batch, spawn batches of six.

Prompt for every hunting agent (fill the placeholders; do not inline the
bundle):

```text
You are a security auditor acting as a malicious prover and a malicious caller.
Your agent id is <ID>. Read your bundle fully before writing anything:
  <bundle path> (<N> lines)
It lists your source shard, the binding table, the inventory items, the
operating procedure, your lens and the shared rules.

The target repository is <repo>. It is read-only: do not create, edit or
delete any file in it, do not run commands that write to it, and do not
install anything or use the network.

Return only FINDING / LEAD blocks as shared-rules.md specifies, each with
detected_by: <ID> exactly (no suffix). A FINDING needs a concrete `proof:`
field; otherwise write a LEAD. Every block carries a `code:` line copied
verbatim from its `location`.
<If stack.json's gnark version is not in the module cache, add:>
gnark std source at the pinned version is not available. Do not reason about
std internals from memory: when a path depends on them, write a LEAD whose
`unverified:` names the std function.
```

Check whether gnark is cached before the first spawn:
`ls "$(go env GOMODCACHE)/github.com/consensys/gnark@<version>"`.

After each agent returns:

1. Save its raw return to `<out>/agents/<ID>.md` (the critic and the judge
   read these).
2. Update the ledger units it owned: `covered` (with `agent_ids` and
   `reviewed_paths`), `candidate` (with `result_fingerprints`), or `blocked`
   (with a reason).

## Turn 5 — Judge

Follow `judging.md`: dedup, completeness line, four gates, severity and
confidence, lead promotion. Write draft records to `<out>/findings.json`.

## Turn 6 — Prove and refute

`--no-poc` skips steps 1, 2 and 5 (no worktree, no PoC). The refuter (step
3) still runs. If the runtime has no `zk-audit:poc-builder` or
`zk-audit:refuter` agent type (the skill folder was copied into
`~/.claude/skills/` without the plugin, or runs from a checkout), spawn a
general-purpose agent and give it the agent file (`{skill}/agents/poc-builder.md`
or `{skill}/agents/refuter.md`) as its brief, with the same tool limits.

1. Create the scratch worktree: `git -C <repo> worktree add --detach <out>/worktree HEAD`.
2. For each confirmed circuit finding (quick: Critical and High only), spawn
   `zk-audit:poc-builder` with the record, the vector's template from
   `poc-templates.md`, and the worktree path. It writes `pocs/<finding-number>_poc_test.go`
   (or `.t.sol`) under `<out>/pocs/`, copies it into the worktree, runs it with
   a time limit and no network, and returns the result.
3. Spawn a fresh `zk-audit:refuter` (or `fp-check`) per confirmed item, with
   the prompt in `judging.md` §6. At most six at once.
4. Update `evidence`, `poc`, `refuter` and confidence in each record.
5. Remove the worktree: `git -C <repo> worktree remove --force <out>/worktree`.

## Turn 7 — Critique

Spawn one coverage critic:

```text
You are the coverage critic. Read <out>/coverage-ledger.json, <out>/inventory.md,
<out>/binding-table.md and the agent outputs in <out>/agents/. List the ledger
units still `planned`, and any hint site, public input, verifier call or
nullifier write that no agent output mentions. Return JSON:
{"missing_units": [{"id": "...", "why": "..."}]}. Do not hunt for bugs.
```

Standard: run one targeted wave (agents for the missing units only, same pool
rules), then judge and prove their output. Deep: also run a final-clean critic
after the last wave. Every unit still open gets `deferred` with a reason.

## Turn 8 — Report

1. Fill the report-only fields of `findings.json` (`posture`,
   `out_of_scope`, `companions`, `hardening`) and close every open ledger unit
   (`deferred` or `blocked`, with a reason).
2. Validate:
   `gnark-inventory validate findings <out>/findings.json` and
   `gnark-inventory validate ledger <out>/coverage-ledger.json`. Fix errors and
   rerun until both pass.
3. Render: `{skill}/scripts/gnark-inventory assemble --out <out> --repo <repo>`.
   It writes `<out>/REPORT.md` per `report-format.md`, or exits 1 and writes
   nothing when an input is invalid. Never edit the report by hand.
4. Print the findings table, the coverage line and the output path.

## Loop mode (`--loop N`, deep)

Run Turns 3–7 N times. Keep `<out>/memory.json`: every fingerprint seen, with
the passes it appeared in. Tag records `NEW` or `KNOWN` and print
`seen in k/N passes`. Stop early when a pass adds no new fingerprint and the
critic returns no missing units.
