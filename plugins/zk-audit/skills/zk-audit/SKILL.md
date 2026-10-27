---
name: zk-audit
description: "Audits zero-knowledge systems built with gnark (Go): circuit soundness, completeness and privacy (hints, range checks, field wraparound, emulated arithmetic, std gadgets, commitments, recursion) and the seams where proofs are consumed (Solidity verifier contracts, public-input binding, nullifiers and replay, VK drift, prover services). Use when the user asks to audit, review, security-check or find bugs in gnark circuits, a ZK verifier integration, a Groth16/PLONK verifier contract, or a gnark version bump; also for /zk-audit, /zk-audit recon, /zk-audit diff. Answers quick ZK questions in guidance mode without spawning agents."
---

# zk-audit

This skill audits gnark circuits and the code that trusts their proofs. It finds
bugs, proves them with a witness or a test where it can, and says honestly what
it did not examine.

Paths below are relative to this skill directory (`{skill}` = the directory that
holds this `SKILL.md`). The plugin root is `{plugin}` = `{skill}/../..`. In
Claude Code, `{plugin}` is also `${CLAUDE_PLUGIN_ROOT}`.

## 1. Pick the mode first

| The user says | Mode | What happens |
|---|---|---|
| "is this circuit ok?", "what does `bits.OmitModulusCheck` do?", "explain this constraint", "why does my proof fail?" | **guidance** | Answer directly from `references/` and the code. No agents, no output directory, no tools beyond Read/Grep. Offer an audit at the end in one line. |
| "audit", "review", "security review", "find bugs", "check this verifier", `/zk-audit ...` | **full audit** | Run the phases in §4. |
| "fix this test", "write a circuit", "speed up the prover" | **not this skill** | Do the task. Mention a security concern only if you see one. |

If the request is ambiguous, use guidance mode. Never start a full audit that
the user did not ask for.

## 2. Invocation

```text
/zk-audit                                  standard profile, whole repo
/zk-audit quick | standard | deep          choose a profile
/zk-audit circuits/transfer.go contracts/Pool.sol   restrict scope to these files
/zk-audit diff origin/main                 review a commit range (also /zk-audit:diff)
/zk-audit recon                            recon only, no hunting (also /zk-audit:recon)
/zk-audit:setup                            show companion skills and tools; install only after consent
```

Flags: `--local` (single agent, no subagents) · `--loop N` (N passes with a
memory ledger; deep default 3) · `--no-poc` (skip PoC generation and
execution) · `--file-output` (also write `REPORT.md` into the target repo) ·
`--out DIR` (override the output directory).

**Profiles**

| Profile | Agents | PoC | Critics | Passes |
|---|---|---|---|---|
| `quick` | vector-scan shards + C1 + I1 + G2 | confirmed Critical/High only | none | 1 |
| `standard` (default) | C1–C6, I1–I4, vector-scan shards, G2, F1 | every confirmed circuit finding | coverage critic + 1 targeted wave | 1 |
| `deep` | everything incl. G1, G3, A1 | every confirmed finding | coverage + final-clean critic | 3 with memory |

Lens ids and their files are listed in `references/orchestration.md`.

Before the first agent spawn, ask **one** question with `AskUserQuestion`
(profile and model, recommended default preselected). If the runtime has no
such tool, use the default and say so in one line. Do not ask anything else
before recon finishes.

## 3. Hard rules (apply to every phase and every agent)

1. **Read-only on the target.** Never edit, create or delete files in the
   audited repository. The only exception is `--file-output`, which writes
   `REPORT.md` only. Every agent prompt carries this clause.
2. **Output outside the repo.** Write everything to
   `~/.zk-audit/<repo-name>/<run-id>/` (run-id = `YYYYMMDD-HHMMSS`), or to
   `--out`.
3. **PoCs run in a scratch git worktree** under the output directory, never in
   the user's checkout: `git -C <repo> worktree add --detach <out>/worktree HEAD`.
   Run them with a time limit and without network
   (`GOFLAGS=-mod=readonly GOPROXY=off timeout 600 go test -run PoC ./...`).
   If the module cache lacks the target's dependencies, ask before running
   `go mod download`. `--no-poc` disables PoCs. Remove the worktree at the end
   (`git -C <repo> worktree remove --force <out>/worktree`).
4. **No silent installs.** Never install a skill, a Go module, `forge` or
   anything else without the user's explicit yes. `/zk-audit:setup` prints the
   exact command first.
5. **A FINDING needs a proof.** A concrete witness, assignment, call sequence or
   a passing PoC. No proof means it is a LEAD. See `references/shared-rules.md`.
6. **Witness generators do not constrain the prover.** Only constraints do. Hint
   code, Go code in `Define` that runs at compile time, frontend validation and
   relayer behaviour are not constraints.
7. **Coverage honesty.** The report never says "verified clean", "secure" or
   "no bugs". It says what was examined, from `coverage-ledger.json`.
8. **No network during the audit**, apart from what the user approves (for
   example in `/zk-audit:setup`, or the one-time build of the inventory tool,
   which fetches `golang.org/x/tools` if it is not cached). The advisory table
   is embedded in the tool.

## 4. Full-audit phases

Print this banner once, then the stack line from Phase 0:

```text
zk-audit · gnark circuits × verifiers × protocol state
profile: <profile> · scope: <scope> · out: <out-dir>
```

Keep a phase table visible and update it as phases move
`Pending → Running → Done | Skipped | Blocked`.

### Phase 0 — Detect (deterministic)

```bash
{plugin}/scripts/gnark-inventory detect --repo <repo> --out <out>/stack.json
```

The wrapper builds the tool on first use (needs Go ≥ 1.24). It reports the gnark
and gnark-crypto versions from `go.mod`, matching advisories, backend and curve
hints, and whether Solidity, Foundry, Hardhat, Circom or Noir are present.

- Any advisory that matches the pinned gnark version is reported as a finding
  candidate right away (see `references/gnark-versions.md` for required
  actions, e.g. regenerate keys).
- `.circom` in scope → delegate to `circom-auditor` if installed, else apply the
  generic vectors in `references/attack-vectors/generic-zk.md`.
- `Nargo.toml` → out of scope for v1. Say so in the report.
- No gnark and no verifier contract → tell the user this skill does not fit and
  stop.

Print one stack line: `gnark v0.x.y (advisories: N) · groth16/plonk · bn254 ·
solidity: yes · foundry: yes · companions: ✔ fp-check ✖ circom-auditor`.
Companion detection rules are in `references/companions.md`.

### Phase 1 — Recon (deterministic tool + one recon pass)

```bash
{plugin}/scripts/gnark-inventory inventory --repo <repo> --out <out> [--files a.go,b.sol]
```

This writes `inventory.json`, `inventory.md`, `binding-table.md` (draft) and a
seeded `coverage-ledger.json`. Then the orchestrator itself (no subagent):

1. Reads `inventory.md` and every circuit's `Define`.
2. Completes `binding-table.md`: one row per public input in public-witness
   order, with its contract source expression, range check, and binding to
   sender / chain / contract / nonce. Unknown cells stay `?`, never guessed.
3. Writes `system-map.md`: actors, trust boundaries, prover → relayer →
   contract flow, trusted parties (setup ceremony, admin, sequencer).
4. Reads `zk-audit.md` at the repo root if present (scope, trusted parties,
   properties, accepted risks, prior findings). Use it to understand intent,
   never to excuse a missing constraint.
5. Validates the ledger: `{plugin}/scripts/gnark-inventory validate ledger <out>/coverage-ledger.json`.

`/zk-audit recon` stops here and prints the system map, the binding table, the
hint inventory, the footgun hits, and threat-model questions for the user. It
offers to draft `zk-audit.md`; it writes it only if the user agrees.

### Phase 2 — Hunt (parallel agents)

Follow `references/orchestration.md`: build one bundle per agent (source shard
path + line count, binding table, `senior-auditor-sop.md`, the lens file,
`shared-rules.md`), run at most **6 agents at a time**, and keep the
`Agent Progress` table current. Agents return FINDING / LEAD blocks only.
`--local` runs the same lenses sequentially in this context.

### Phase 3 — Judge

Follow `references/judging.md`: dedup by `group_key` (never across circuits or
functions; keep distinct fixes as Option A/B), run the four gates once per item,
assign severity and confidence, apply lead promotion, print the completeness
line. Reject the rationalizations in §6.

### Phase 4 — Prove

For every `confirmed` circuit soundness finding (unless `--no-poc`), spawn
the `poc-builder` agent with the finding and the template named by its vector
(`references/poc-templates.md`). It writes a Go test in the scratch worktree that
shows a false statement verifying, plus the honest control case. Contract
findings get a Foundry test when `forge` exists. Then a **fresh refuter** that
did not see the hunt starts from `refuted: true` and must re-derive the bug
from source (delegate to `fp-check` if installed). A PoC that does not compile
or does not show the bug sets `evidence: ANALYSIS` and lowers confidence.

### Phase 5 — Critique

A coverage critic reads `coverage-ledger.json` and all agent outputs and returns
`missing_units` (a hint never analysed, a public input with no binding row, a
verifier function never read). Standard runs one extra targeted wave on them;
deep also runs a final-clean critic. Units left open stay `planned` or
`deferred` in the ledger with a reason.

### Phase 6 — Report

Write `findings.json` (schema in `{plugin}/schemas/findings.schema.json`) and
validate it:

```bash
{plugin}/scripts/gnark-inventory validate findings <out>/findings.json
{plugin}/scripts/gnark-inventory validate ledger <out>/coverage-ledger.json
```

Fix every validation error before you continue. Then render `REPORT.md` with
the structure in `references/report-format.md` and print the report path and
the findings table. Do not re-judge or re-word findings while rendering.

## 5. Companions

Delegate when a companion is installed, use the embedded fallback when it is
not, and never install silently. Delegated results become records in our
`findings.json` with `detected_by: <companion>`.

| Need | Companion | Fallback |
|---|---|---|
| `.circom` in scope | `circom-auditor` (zkSecurity) | `attack-vectors/generic-zk.md` |
| Solidity beyond the ZK integration | `solidity-auditor`, `x-ray` (pashov) | I1–I3 only; the report says so |
| Per-function context | `audit-context-building` (Trail of Bits) | Phase 1 recon |
| Circuit vs spec | `spec-to-code-compliance` (Trail of Bits) | C6 lens |
| False-positive check | `fp-check`, `vulnerability-triage-brocards` (Trail of Bits) | embedded refuter in `judging.md` |
| Variants of a finding | `variant-analysis` (Trail of Bits) | grep `inventory.json` for the same shape |
| `go.mod` risk | `supply-chain-risk-auditor` (Trail of Bits) | `gnark-versions.md` check |
| PR review | `differential-review` (Trail of Bits) | `/zk-audit diff` |

Details and detection: `references/companions.md`.

## 6. Rationalizations to reject

When you (or an agent) reach for one of these to dismiss a candidate, stop. It
is not a refutation. The full table with the reason each fails is in
`references/rationalizations.md`.

| Rationalization | Why it fails |
|---|---|
| "The test suite passes." | Tests run the honest witness. Under-constraint never fails a test. |
| "The hint computes it correctly." | The prover chooses hint outputs. Only constraints bind them. |
| "`test.IsSolved` / `assert.ProverSucceeded` is green." | Both use honest hints. Use `solver.OverrideHint` via `test.WithSolverOpts`, or `test.WithInvalidAssignment`. |
| "The frontend / relayer validates it." | A malicious prover skips the frontend and calls the contract directly. |
| "Only our relayer submits proofs." | Proofs and calldata are public in the mempool; anyone can copy or front-run them. |
| "gnark std is audited." | GHSA-3mvx-pp85-pm65 lists 11 std bugs of exactly this shape. Check the pinned version and the gadget's contract. |
| "It's checked in Go before `Define` returns." | Go `if` statements in `Define` run at compile time on placeholder values, not on the witness. |
| "That value can never be ≥ r." | Field elements wrap; the prover picks `r − k`. |
| "The verifier contract was generated by gnark, so it's fine." | It is only as good as its VK, its gnark version and how the caller builds inputs. |
| "Groth16 proofs are unique, so the proof hash is a good nullifier." | Groth16 proofs are malleable. |
| "Only the admin can call it." | Demote, do not drop: name the amplifier or record it as a trusted-party assumption. |

## 7. Output contract

`~/.zk-audit/<repo>/<run-id>/` contains `stack.json`, `inventory.json`,
`inventory.md`, `binding-table.md`, `system-map.md`, `coverage-ledger.json`,
`findings.json`, `REPORT.md`, `pocs/`, and `bundles/`. Every finding carries
`verdict` (`confirmed` / `needs_validation` / `rejected`), `severity`,
`confidence` (0–100), `evidence` (`POC` / `ANALYSIS`) and `detected_by`.

## 8. References (load on demand, one level deep)

| File | Load when |
|---|---|
| `references/orchestration.md` | Before Phase 2 in delegated mode |
| `references/shared-rules.md` | Inside every agent bundle; before writing any FINDING/LEAD |
| `references/senior-auditor-sop.md` | Inside every agent bundle; in `--local` mode before hunting |
| `references/agents/*.md` | One lens per bundle |
| `references/attack-vectors/index.md` | Vector-scan shards; guidance answers about known bug shapes |
| `references/attack-vectors/*.md` | One slice per vector-scan shard |
| `references/gnark-api-footguns.md` | Any question about what a gnark API constrains |
| `references/gnark-versions.md` | Phase 0; any version or upgrade question |
| `references/judging.md` | Phase 3; any "is this real?" question |
| `references/poc-templates.md` | Phase 4 |
| `references/rationalizations.md` | Phase 3 and refuter prompts |
| `references/report-format.md` | Phase 6 |
| `references/companions.md` | Phase 0 and `/zk-audit:setup` |
