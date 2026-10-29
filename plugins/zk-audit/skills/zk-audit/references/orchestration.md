# Orchestration (delegated mode)

<!-- Turn structure, bounded worker pool and progress console adapted from zkSecurity zk-skills circom-auditor orchestration/claude.md (MIT, (c) 2026 zkSecurity); profiles and critic waves from Cloudflare security-audit-skill (MIT, (c) 2025-2026 Cloudflare, Inc.). -->

Use this when the runtime can spawn subagents (Claude Code `Agent`). With
`--local`, or without subagents, run the same lenses one after another in this
context and skip the progress console.

Write the prompts in plain, runtime-neutral language. Never ask an agent to
install, write into the target repo, or use the network.

## Agents

<!-- generated:agent-table from profiles.json (make sync-profiles); do not edit -->

| Id | Lens | Lens file | Group | Shard | Profiles |
|---|---|---|---|---|---|
| C1 | hint soundness | `agents/C1-hint-soundness.md` | circuit | circuit | quick, standard, deep |
| C2 | range and decomposition | `agents/C2-range-decomposition.md` | circuit | circuit | standard, deep |
| C3 | field arithmetic | `agents/C3-field-arithmetic.md` | circuit | circuit | standard, deep |
| C4 | control flow and selectors | `agents/C4-control-selector.md` | circuit | circuit | standard, deep |
| C5 | cryptographic gadgets | `agents/C5-crypto-gadgets.md` | circuit | circuit | standard, deep |
| C6 | specification and invariants | `agents/C6-spec-invariant.md` | circuit | all | standard, deep |
| I1 | public-input binding | `agents/I1-public-input-binding.md` | integration | integration | quick, standard, deep |
| I2 | verifier contracts | `agents/I2-verifier-contract.md` | integration | integration | standard, deep |
| I3 | protocol state | `agents/I3-protocol-state.md` | integration | integration | standard, deep |
| I4 | prover service | `agents/I4-prover-service.md` | integration | prover | standard, deep |
| V-hints | vector scan: hints | `agents/vector-scan.md` + `attack-vectors/hints.md` | vector scan | circuit | quick, standard, deep |
| V-range | vector scan: range and bits | `agents/vector-scan.md` + `attack-vectors/range-bits.md` | vector scan | circuit | quick, standard, deep |
| V-field | vector scan: field arithmetic | `agents/vector-scan.md` + `attack-vectors/field-arith.md` | vector scan | circuit | quick, standard, deep |
| V-selector | vector scan: selectors and control | `agents/vector-scan.md` + `attack-vectors/selector-control.md` | vector scan | circuit | quick, standard, deep |
| V-hash | vector scan: hashes and Merkle | `agents/vector-scan.md` + `attack-vectors/hash-merkle.md` | vector scan | circuit | quick, standard, deep |
| V-curves | vector scan: curves and signatures | `agents/vector-scan.md` + `attack-vectors/curves-signatures.md` | vector scan | circuit | quick, standard, deep |
| V-commit | vector scan: commitments and recursion | `agents/vector-scan.md` + `attack-vectors/commitments-recursion.md` | vector scan | circuit | quick, standard, deep |
| V-generic | vector scan: generic ZK | `agents/vector-scan.md` + `attack-vectors/generic-zk.md` | vector scan | circuit | quick, standard, deep |
| V-pubin | vector scan: public inputs | `agents/vector-scan.md` + `attack-vectors/public-inputs.md` | vector scan | integration | quick, standard, deep |
| V-verifier | vector scan: verifier contracts | `agents/vector-scan.md` + `attack-vectors/verifier-contracts.md` | vector scan | integration | quick, standard, deep |
| V-state | vector scan: protocol state | `agents/vector-scan.md` + `attack-vectors/protocol-state.md` | vector scan | integration | quick, standard, deep |
| V-prover | vector scan: prover service | `agents/vector-scan.md` + `attack-vectors/prover-service.md` | vector scan | prover | quick, standard, deep |
| G1 | numerical gaps | `agents/G1-numerical-gap.md` | gap | circuit | deep |
| G2 | binding gaps | `agents/G2-binding-gap.md` | gap | all | quick, standard, deep |
| G3 | composition gaps | `agents/G3-composition-gap.md` | gap | circuit | deep |
| A1 | asymmetry | `agents/A1-asymmetry.md` | cross | all | deep |
| F1 | first principles | `agents/F1-first-principles.md` | cross | all | standard, deep |

- **quick**: C1, I1, G2 + 12 vector-scan shards (V-*).
- **standard**: C1, C2, C3, C4, C5, C6, I1, I2, I3, I4, G2, F1 + 12 vector-scan shards (V-*).
- **deep**: C1, C2, C3, C4, C5, C6, I1, I2, I3, I4, G1, G2, G3, A1, F1 + 12 vector-scan shards (V-*).

<!-- end generated:agent-table -->

Deep repeats the hunt for 3 passes with memory (Loop mode below). Skip agents whose shard is empty (for example no
Solidity means no I1–I3 or integration V-shards); mark them `Skipped` with the
reason, and record their ledger units as `not_applicable`.

## Turn 1 — Discover

Resolve `{skill}` (`SKILL.md`, first paragraph), read `{skill}/VERSION`,
print the banner from `SKILL.md` and the phase table (all `Pending`). Then, in
parallel:

1. Parse the invocation (`{skill}/scripts/gnark-inventory args --repo <repo> -- <words>`,
   `SKILL.md` §2) and create its `out` directory.
2. Run Phase 0: `{skill}/scripts/gnark-inventory detect --repo <repo> --out <out>/stack.json`.
3. Detect companions (`companions.md`).
4. Run the update check: `{skill}/scripts/check-version` (silent unless a
   newer release exists; never blocks the audit).

Print the stack line and the companion line. Ask the single profile/model
question (`AskUserQuestion`), or state the default, then print
`profile: <profile> · model: <model>`.

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
`Pending`, omitted agents `Skipped` (the status words of the phase table in
`SKILL.md`):

```markdown
## Agent Progress

| Agent | Lens | Shard | Status | Result |
|---|---|---|---|---|
| V-hints | vector scan: hints | circuit | Running | – |
| C1 | hint soundness | circuit | Running | – |
| I1 | public-input binding | integration | Running | – |
| G2 | binding gaps | all | Pending | – |
```

Spawn at most six agents at once. When one returns, mark it `Done` with a
count (`2 findings, 1 lead`), or `Blocked` with the reason, then start the
next `Pending` agent. Print the updated table after each batch. If the runtime
returns parallel results only per batch, spawn batches of six.

Spawn every hunter as the **`zk-audit:hunter`** agent type. In a plugin
install it has only Read, Grep and Glob, so it cannot write to the target or
run commands whatever the prompt says. Where that type does not exist (the
skill folder copied alone into `~/.claude/skills/`, or run from a checkout),
spawn a general-purpose agent, put the body of `{skill}/agents/hunter.md`
first in its prompt, and add: "Use only the Read, Grep and Glob tools." In
that fallback read-only holds by prompt only; say so once in the run summary.

Prompt (fill the placeholders; do not inline the bundle):

```text
Your agent id is <ID>. Your bundle is <bundle path> (<N> lines).
The target repository is <repo>; it is read-only.
Return only FINDING / LEAD blocks with detected_by: <ID>.
```

The bundle names the gnark std directory at the pinned version, or says it is
not in the module cache (the hunter then writes LEADs instead of reasoning
about std from memory).

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

Spawn one coverage critic as the **`zk-audit:critic`** agent type (Read,
Grep and Glob only), or, without the plugin, a general-purpose agent briefed
with `{skill}/agents/critic.md` and told to use only Read, Grep and Glob:

```text
Role: coverage. The audit output directory is <out>.
```

It returns `{"missing_units": [...]}` per its brief.

Standard: run one targeted wave (agents for the missing units only, same pool
rules), then judge and prove their output. Deep: also run a final-clean critic
after the last wave (`zk-audit:critic`, prompt `Role: final-clean. The audit
output directory is <out>.`) and fix or downgrade every claim it lists as
unsupported. `gnark-inventory profiles --profile <profile>` lists the
profile's critics and targeted waves. Every unit still open gets `deferred` with a reason.

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
