---
name: zk-audit
description: "Audits zero-knowledge systems built with gnark (Go): circuit soundness, completeness and privacy (hints, range checks, field wraparound, emulated arithmetic, std gadgets, commitments, recursion) and the seams where proofs are consumed (Solidity verifier contracts, public-input binding, nullifiers and replay, VK drift, prover services). Use when the user asks to audit, review, security-check or find bugs in gnark circuits, a ZK verifier integration, a Groth16/PLONK verifier contract, or a gnark version bump; also for /zk-audit, /zk-audit recon, /zk-audit diff, /zk-audit setup. Answers quick ZK questions in guidance mode without spawning agents."
---

# zk-audit

This skill audits gnark circuits and the code that trusts their proofs. It finds
bugs, proves them with a witness or a test where it can, and says honestly what
it did not examine.

`{skill}` is the directory that holds this `SKILL.md`. Resolve it from the
path this skill was loaded from (Claude Code prints it as the skill's base
directory); otherwise use the first of `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`,
`~/.claude/skills/zk-audit` and `.claude/skills/zk-audit` that holds this file.
The skill folder is self-contained: everything below lives under `{skill}`
(`scripts/`, `tools/gnark-inventory/`, `schemas/`, `agents/`, `references/`,
`VERSION`), so it works the same installed as a plugin or copied alone into
`~/.claude/skills/zk-audit`. Never resolve a path outside `{skill}`.

## 1. Pick the mode first

| The user says | Mode | What happens |
|---|---|---|
| "is this circuit ok?", "what does `bits.OmitModulusCheck` do?", "explain this constraint", "why does my proof fail?" | **guidance** | Answer directly from `references/` and the code. No agents, no output directory, no tools beyond Read/Grep. Offer an audit at the end in one line. |
| "audit", "review", "security review", "find bugs", "check this verifier", `/zk-audit ...` | **full audit** | Run the phases in §4. |
| `/zk-audit setup`, `recon` or `diff` (or `/zk-audit:setup` etc.) | **setup / recon / diff** | Follow `references/modes/<mode>.md`. |
| "fix this test", "write a circuit", "speed up the prover" | **not this skill** | Do the task. Mention a security concern only if you see one. |

If the request is ambiguous, use guidance mode. Never start a full audit that
the user did not ask for.

## 2. Invocation

```text
/zk-audit                                  standard profile, whole repo
/zk-audit quick | standard | deep          choose a profile
/zk-audit circuits/vote.go contracts/Ballot.sol   restrict scope to these files
/zk-audit diff origin/main                 review a commit range (also /zk-audit:diff)
/zk-audit recon                            recon only, no hunting (also /zk-audit:recon)
/zk-audit setup                            show companion skills and tools; install only after consent (also /zk-audit:setup)
```

The `/zk-audit:<mode>` commands exist only in a plugin install; the
`/zk-audit <mode>` form works in every install.

Flags: `--local` (single agent, no subagents) · `--loop N` (N passes with a
memory ledger; default: the profile's passes) · `--no-poc` (skip PoC generation and
execution; the refuter still runs) · `--file-output` (also write `REPORT.md` into the target repo) ·
`--out DIR` (override the output directory) · `--profile P` (same as the bare
profile word).

Never parse the invocation by hand. Pass the words after `/zk-audit` to the
tool (`--mode <mode>` when a `/zk-audit:<mode>` command started the run):

```bash
{skill}/scripts/gnark-inventory args --repo <repo> -- <words>
```

It prints JSON: `mode`, `profile` and `profile_explicit`, `scope`, `local`,
`passes` and `memory`, `poc`, `file_output` and `report_copy`, `out`,
`run_id`, `diff` (`base`, `head`) and `warnings`. Exit 1 lists every problem
(unknown flag, missing scope file, `--out` inside the repository): show them
to the user and stop. Use its `out`, `run_id`, `scope` and `passes` below.

**Profiles**

<!-- generated:profile-table from profiles.json (make sync-profiles); do not edit -->

| Profile | Agents | PoC | Refuters | Critics | Passes |
|---|---|---|---|---|---|
| `quick` | C1, I1, G2 + 12 vector-scan shards (V-*) | confirmed Critical/High circuit findings only | one per confirmed finding (also with --no-poc) | none | 1 |
| `standard` (default) | C1, C2, C3, C4, C5, C6, I1, I2, I3, I4, G2, F1 + 12 vector-scan shards (V-*) | every confirmed circuit finding | one per confirmed finding | coverage critic + 1 targeted wave | 1 |
| `deep` | C1, C2, C3, C4, C5, C6, I1, I2, I3, I4, G1, G2, G3, A1, F1 + 12 vector-scan shards (V-*) | every confirmed finding | one per confirmed finding | coverage critic + final-clean critic + 1 targeted wave | 3 with memory |

<!-- end generated:profile-table -->

Lens ids and their files are listed in `references/orchestration.md`. The tool
prints the same definitions as JSON: `{skill}/scripts/gnark-inventory profiles [--profile P]`.

Before the first agent spawn, ask **one** question with `AskUserQuestion`
(profile and model, recommended default preselected). If the runtime has no
such tool, use the default and say so in one line. Do not ask anything else
before recon finishes.

## 3. Hard rules (apply to every phase and every agent)

1. **Read-only on the target.** Never edit, create or delete files in the
   audited repository. The only exceptions are `--file-output`, which writes
   the report copy only, and the `zk-audit.md` that recon drafts after the
   user says yes. Every agent prompt carries this clause.
2. **Output outside the repo.** Write everything to
   `~/.zk-audit/<repo-name>/<run-id>/` (run-id = `YYYYMMDD-HHMMSS`), or to
   `--out`.
3. **PoCs run in a scratch git worktree, inside the sandbox.** Never in the
   user's checkout: `git -C <repo> worktree add --detach <out>/worktree HEAD`.
   Every command that executes target code (PoC `go test`, `forge test`) goes
   through `{skill}/scripts/sandbox`, with the worktree the only writable
   tree:

   ```bash
   {skill}/scripts/sandbox --rw <out>/worktree --ro <repo> -- go -C <out>/worktree test -count=1 -run PoC_ ./<pkg>/
   {skill}/scripts/sandbox --rw <out>/worktree --ro <repo> -- forge test --root <out>/worktree --offline --match-contract PoC_
   ```

   On Linux it uses bubblewrap: no network, read-only file system except the
   `--rw` directories, home directory hidden, cgo off, local toolchain only,
   `GOFLAGS=-mod=mod`, `GOPROXY=off`, a memory limit and a 600 s time limit
   (exit 124). On macOS it uses `sandbox-exec` (network and writes denied;
   reads not restricted). Without either it prints a warning and applies only
   the limits; say so in the report's posture. `-mod=mod` lets the go command
   add `go.sum` lines for test-only imports such as `gnark/test` from the
   module cache; it only rewrites the worktree's `go.mod`. If the module
   cache lacks the target's dependencies, ask before running `go mod
   download`. `--no-poc` disables PoCs. Remove the worktree at the end
   (`git -C <repo> worktree remove --force <out>/worktree`).
4. **No silent installs.** Never install a skill, a Go module, `forge` or
   anything else without the user's explicit yes. `/zk-audit setup` prints the
   exact command first.
5. **A FINDING needs a proof.** A concrete witness, assignment, call sequence or
   a passing PoC. No proof means it is a LEAD. See `references/shared-rules.md`.
6. **Witness generators do not constrain the prover.** Only constraints do. Hint
   code, Go code in `Define` that runs at compile time, frontend validation and
   relayer behaviour are not constraints.
7. **Coverage honesty.** The report never says "verified clean", "secure" or
   "no bugs". It says what was examined, from `coverage-ledger.json`.
8. **No network during the audit**, apart from what the user approves (for
   example in `/zk-audit setup`) and the update check
   (`{skill}/scripts/check-version`: one GET of the public `VERSION` file with
   a 3 s limit, nothing about the target is sent; `ZK_AUDIT_NO_UPDATE_CHECK=1`
   turns it off). The inventory tool builds offline from vendored sources and
   the advisory table is embedded in it.

## 4. Full-audit phases

Before anything else, print this banner once (`<version>` from
`{skill}/VERSION`):

```text
zk-audit v<version> · gnark circuits × verifiers × protocol state
scope: <scope> · out: <out-dir>
```

Run every command as one simple command: no `cd … &&`, `;`, pipes or
`$(...)` (permission allowlists refuse compound commands); use `go -C <dir>`,
`git -C <dir>` and `forge --root <dir>` instead of `cd`, and Read instead of
`cat`.

In the same turn run `{skill}/scripts/check-version` alongside Phase 0. It is
silent unless a newer release exists; print its one line if it prints one,
and never wait on or retry it. After Phase 0 print the stack line, then, once
the profile question is answered, `profile: <profile> · model: <model>`.

Keep this phase table visible and reprint it whenever a status changes. Status
moves `Pending → Running → Done | Skipped | Blocked`; exactly one phase is
`Running` at a time. Where the runtime has a todo tool (Claude Code
`TodoWrite`), mirror the seven phases there with the same transitions.

```markdown
## zk-audit Progress

| Phase | Status | Result |
|---|---|---|
| 0 Detect | Done | gnark v0.x.y · advisories: 2 |
| 1 Recon | Running | – |
| 2 Hunt | Pending | – |
| 3 Judge | Pending | – |
| 4 Prove | Pending | – |
| 5 Critique | Pending | – |
| 6 Report | Pending | – |
```

During Phase 2 the `Agent Progress` table in `references/orchestration.md`
uses the same status words.

### Phase 0 — Detect (deterministic)

```bash
{skill}/scripts/gnark-inventory detect --repo <repo> --out <out>/stack.json
```

The wrapper builds the tool on first use (needs Go ≥ 1.24). It reports the gnark
and gnark-crypto versions from `go.mod`, matching advisories, backend and curve
hints, and whether Solidity, Foundry, Hardhat, Circom or Noir are present.

- Check the sandbox: `{skill}/scripts/sandbox --check`. It prints the engine
  (`bwrap`, `sandbox-exec` or `none`) and what it isolates; add it to the
  stack line.
- Any advisory that matches the pinned gnark version is reported as a finding
  candidate right away (see `references/gnark-versions.md` for required
  actions, e.g. regenerate keys).
- `.circom` in scope → delegate to `circom-auditor` if installed, else apply the
  generic vectors in `references/attack-vectors/generic-zk.md`.
- `Nargo.toml` → out of scope for v1. Say so in the report.
- No gnark and no verifier contract → tell the user this skill does not fit and
  stop.

Print one stack line: `gnark v0.x.y (advisories: N) · groth16/plonk · bn254 ·
solidity: yes · foundry: yes · sandbox: bwrap · companions: ✔ fp-check ✖ circom-auditor`.
Companion detection rules are in `references/companions.md`.

### Phase 1 — Recon (deterministic tool + one recon pass)

```bash
{skill}/scripts/gnark-inventory inventory --repo <repo> --out <out> [--files a.go,b.sol]
```

This writes `inventory.json`, `inventory.md`, `binding-table.md` (draft) and a
seeded `coverage-ledger.json`. Type loading runs the go command on the target,
so the tool runs it inside the same sandbox as PoCs (repository read-only,
only `<out>` writable, no network); `--sandbox on` makes a missing sandbox an
error, `--sandbox off` loads in-process. Then the orchestrator itself (no subagent):

1. Reads `inventory.md` and every circuit's `Define`.
2. Completes `binding-table.md`: one row per public input in public-witness
   order, with its contract source expression, range check, and binding to
   sender / chain / contract / nonce. Unknown cells stay `?`, never guessed.
   Write facts and source expressions only, no verdicts ("free", "unbound",
   "bug"): the table is inlined into every bundle and must not steer the
   hunters.
3. Writes `system-map.md`: actors, trust boundaries, prover → relayer →
   contract flow, trusted parties (setup ceremony, admin, sequencer).
4. Reads `zk-audit.md` at the repo root if present (scope, trusted parties,
   properties, accepted risks, prior findings). Use it to understand intent,
   never to excuse a missing constraint.
5. Validates the ledger: `{skill}/scripts/gnark-inventory validate ledger <out>/coverage-ledger.json`.

`/zk-audit recon` stops here and prints the system map, the binding table, the
hint inventory, the footgun hits, and threat-model questions for the user. It
offers to draft `zk-audit.md`; it writes it only if the user agrees.

### Phase 2 — Hunt (parallel agents)

Build one bundle per selected agent, then follow `references/orchestration.md`:

```bash
{skill}/scripts/gnark-inventory bundle --out <out> --skill {skill} --profile <profile>
```

A bundle lists its source shard as paths with line counts (source is never
inlined) and inlines the binding table, the inventory items for those files,
`senior-auditor-sop.md`, the lens file and `shared-rules.md`. Spawn each
hunter as the `zk-audit:hunter` agent type (plugin install: Read, Grep and
Glob only), else a general-purpose agent briefed with `{skill}/agents/hunter.md`
and limited to those tools by prompt. Run at most **6
agents at a time** and keep the `Agent Progress` table current. Agents return
FINDING / LEAD blocks only. `--local` runs the same lenses one after another in
this context. With more than one pass (deep, `--loop N`), follow "Loop mode" in
`references/orchestration.md`: `gnark-inventory memory` holds the
fingerprints, NEW / KNOWN tags and the stop rule.

### Phase 3 — Judge

Follow `references/judging.md`: dedup by `group_key` (never across circuits or
functions; keep distinct fixes as Option A/B), run the four gates once per item,
assign severity and confidence, apply lead promotion, print the completeness
line. Reject the rationalizations in §6.

### Phase 4 — Prove

For every `confirmed` circuit soundness finding (unless `--no-poc`), spawn
the `zk-audit:poc-builder` agent (plugin install) or, where that agent type
does not exist, a general-purpose agent briefed with `{skill}/agents/poc-builder.md`
and the same tool limits. Give it the finding and the template named by its vector
(`references/poc-templates.md`). It writes a Go test in the scratch worktree that
shows a false statement verifying, plus the honest control case. Contract
findings get a Foundry test when `forge` exists. Then a **fresh refuter** that
did not see the hunt starts from `refuted: true` and must re-derive the bug
from source (`fp-check` if installed, else `zk-audit:refuter`, else a
general-purpose agent briefed with `{skill}/agents/refuter.md`). A PoC that does not compile
or does not show the bug sets `evidence: ANALYSIS` and lowers confidence; a
PoC on a model circuit is `poc.result: demonstrated_on_model` with
`ANALYSIS`. Every PoC stays in `<out>/pocs/` and on its record, also when the
record is later demoted.

### Phase 5 — Critique

A coverage critic (`zk-audit:critic`, else a general-purpose agent briefed
with `{skill}/agents/critic.md`; read-only) reads `coverage-ledger.json` and all agent outputs and returns
`missing_units` (a hint never analysed, a public input with no binding row, a
verifier function never read). Standard runs one extra targeted wave on them;
deep also runs a final-clean critic. Units left open stay `planned` or
`deferred` in the ledger with a reason.

### Phase 6 — Report

1. Write `findings.json` (schema in `{skill}/schemas/findings.schema.json`).
   Besides `records`, fill the report-only fields the assembler cannot
   derive: `posture` (three to six sentences), `out_of_scope`, `companions`
   (`present` / `missing`) and `hardening`. With zero records, set
   `no_findings: true` and a `no_findings_reason` that says what was examined.
2. Close the ledger with the tool, never by rewriting the file: every unit
   still `planned` or `in_progress` becomes `deferred` or `blocked` with a
   `reason`, and every `candidate` unit is judged and becomes `covered`
   (`{skill}/scripts/gnark-inventory ledger mark --out <out> --from planned --status deferred --reason "<why>"`;
   `ledger show --out <out>` prints the counts).
3. Validate both files and fix every error. `--out` checks the evidence on
   disk: every `poc.path` under `<out>/pocs/`, and an output in
   `<out>/agents/` for every agent of a `covered` unit:

   ```bash
   {skill}/scripts/gnark-inventory validate findings <out>/findings.json --out <out>
   {skill}/scripts/gnark-inventory validate ledger <out>/coverage-ledger.json --out <out>
   ```

4. Render the report with the deterministic assembler. It validates again,
   refuses invalid input (exit 1, no report), quotes the constraint lines
   verbatim from `<repo>` and computes coverage only from the ledger:

   ```bash
   {skill}/scripts/gnark-inventory assemble --out <out> --repo <repo>
   ```

   Read its warnings (a ledger fingerprint missing from `findings.json`, a unit
   still planned or candidate, a PoC file no record names). Fix the inputs and
   rerun; never edit `REPORT.md` by hand. It also writes
   `<out>/pocs/MANIFEST.json` (each PoC file, its hash, record, package and
   command) so a PoC can be re-run after the worktree is removed.
5. With `--file-output`, add `--file-output` to the assemble command; it also
   writes `<repo>/zk-audit-report-<run-id>.md`. The tool refuses every other
   output path inside the repository (exit 2).
6. Print the report path, the findings table and the coverage line.

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
`findings.json`, `REPORT.md`, `pocs/` (with `MANIFEST.json`), `agents/`, and `bundles/`. Every finding carries
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
| `references/companions.md` | Phase 0 and setup mode |
| `references/modes/*.md` | `/zk-audit setup`, `recon`, `diff` |
