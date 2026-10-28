# zk-audit: plan

This plan covers a Claude Code plugin that audits ZK systems end to end. It starts with **gnark circuits** and covers how they integrate with **verifier contracts, protocol state and off-chain prover services**. The design lets other frontends plug in later.

The research behind it is in [`docs/research.md`](docs/research.md).
Where the implementation differs from this plan (for example `detect`,
`bundle` and `assemble` are subcommands of the Go tool rather than separate
`scripts/`, and the tool, scripts and schemas live inside the self-contained
skill folder), [`docs/design-notes.md`](docs/design-notes.md) records it; the
built system is described in [`docs/x-ray/`](docs/x-ray/x-ray.md).

---

## 1. Goals and non-goals

**Goals**

1. **Find soundness, completeness and privacy bugs in gnark circuits.** This includes hints, range checks, field wraparound, emulated arithmetic, std gadgets, commitments and recursion.
2. **Find bugs at the seams.** That means circuit ↔ verifier contract ↔ protocol state ↔ prover service. Public-input binding, nullifiers, replay, VK drift and malleability all belong here. Existing skills cover this least, and real money is lost here most.
3. **Prove findings, not just describe them.** A confirmed soundness finding comes with a runnable Go test showing that a forged witness verifies, built with `solver.OverrideHint` or a hand-built assignment. Contract-side findings come with a Foundry test where feasible.
4. **Give a smooth developer experience.**
   - One install command and one slash command.
   - The skill detects the stack itself.
   - It uses companion skills when they are present and has an embedded fallback when they are not.
   - It never surprises the user with an auto-install or with writes into their repo.
5. **Be honest about coverage.** A coverage ledger records what was actually examined, and the report never claims more.

**Non-goals for v1**

- Auditing gnark-crypto or the gnark backends themselves. We treat them as peripheral and check only for known-vulnerable versions.
- Native Circom, Noir and Halo2 engines. We route to existing skills instead (§6).
- Formal verification. We only describe how to hand off to Lean work later.

---

## 2. What we borrow from each reference

| Source | Take | Leave |
|---|---|---|
| **zkSecurity `circom-auditor`** (MIT) | Context builder that separates in-scope and peripheral code. Bundle-per-agent with path and line count instead of inlined source. Vector-scan shards with the `Skip/Drop/Investigate` gate. Gap hunters. `FINDING` needs a proof, otherwise it is a `LEAD`. 4 judging gates, including "witness generators don't constrain the prover; only constraints do". Fresh-context triager. Eval sanitisation. | Its Circom vocabulary, banner and marketing. Full source duplicated in all 17 bundles. Its confidence-only scoring. |
| **zkao** | A committed guidance file (`zk-audit.md`) for threat model, trusted parties and accepted risks. Free recon before expensive hunting. `diff` and continuous modes. Evidence type `POC` or `ANALYSIS` on each finding. Dedup across runs. | Its closed engine. It is an optional paid backend only (§6). |
| **pashov `solidity-auditor` / `x-ray`** (MIT) | Senior-auditor SOP (Feynman, Socratic, Inversion). Asymmetry lens. Memory ledger and `--loop` with KNOWN/NEW tags. A **deterministic report assembler** with no model judgment. The coverage-honesty rule. A read-only clause in every agent prompt. x-ray-style invariant synthesis (guard lift plus a check of every write site). | Its Solidity lenses: we delegate those to the skill itself. Auto `git clone` installs. |
| **Cloudflare `security-audit`** (MIT) | Coverage ledger made of deterministic units, checked by a validator. Coverage critic plus a final-clean critic. A verifier that did not find the issue ("You did not write this"). Verdicts `confirmed` / `needs_validation` / `rejected`, enforced by JSON schema. Quick, standard and deep profiles with a budget. Output written **outside** the target repo. Sandboxed execution. | Its web, cloud and mobile attack-class files. |
| **Trail of Bits skills** (CC BY-SA 4.0) | Marketplace and plugin packaging. Router SKILL.md that hands off to schema-bound workflow fan-outs. Refuters that start from `refuted: true`. "Rationalizations to Reject" table. SKILL.md under 500 lines with references one level deep. `case.yaml` evals scored as Δ against a baseline, with an all-safe panel and negative-trigger cases. **Delegation targets** listed in §6. | We **delegate to** ToB skills and do not copy their text. Copying their text would force CC BY-SA on us; delegating keeps the license choice open (§10 Q1). |

We fill a real gap here. **None** of the five covers gnark, and none seriously covers ZK verifier integration. zkbugs has exactly one gnark entry. The only automated gnark auditor is zkao, which is closed.

---

## 3. Developer experience

**Install**

```text
/plugin marketplace add shramee/zk-audit
/plugin install zk-audit@zk-audit
```

**Use**

| Command | What it does |
|---|---|
| `/zk-audit` | Auto-detects the stack and runs the **standard** profile on the whole repo. |
| `/zk-audit quick` · `deep` | Selects a profile. `quick` is about 10 minutes with recon, vector scan and judging. `deep` adds gap hunters, PoC for every finding, two critics and three passes. |
| `/zk-audit circuits/transfer.go contracts/Pool.sol` | Limits scope to the named files. |
| `/zk-audit diff origin/main` | PR or commit-range review. Removed `Assert*` calls, changed public-input order, gnark bumps and regenerated verifiers count as high-risk triggers. |
| `/zk-audit recon` | Recon only. Produces a system map, a public-input table, a hint inventory and threat-model questions, with no hunting. It is cheap, and a good first step. |
| `/zk-audit:setup` | Reports which companion skills and tools (go, semgrep, foundry, slither) are present. Prints the exact install command for each missing one, and runs it only after the user confirms. |
| `--local` · `--loop N` · `--no-poc` · `--file-output` | Run single-agent, run N passes with memory, skip PoC generation, or write the report into the repo. |

When the request is ambiguous, for example "is this circuit ok?", the skill answers in **guidance mode** with a direct answer and spawns no agents. It enters full-audit mode only when the user asks for an audit or review. This follows Cloudflare's approach.

Before the first spawn it asks **one** question: profile and model, with a recommended default. On runtimes without `AskUserQuestion` it uses the default and says so.

**Output**

Output goes to `~/.zk-audit/<repo>/<run-id>/`:

- `REPORT.md`
- `findings.json`
- `coverage-ledger.json`
- `pocs/`
- `system-map.md`

The skill never writes into the target repo unless `--file-output` is given. PoCs run in a scratch git worktree.

**Repo guidance file**

An optional `zk-audit.md` at the target's root holds:

- scope
- trusted parties (sequencer, setup ceremony, admin)
- the properties that must hold
- accepted risks
- prior findings

`/zk-audit recon` can draft it.

---

## 4. Architecture

```
/zk-audit
  Phase 0  Detect      → stack fingerprint (gnark? circom? noir? solidity? backend+curve? gnark version?)
  Phase 1  Recon       → system map, public-input binding table, hint & gadget inventory, ledger seeded
  Phase 2  Hunt        → parallel lens agents over bundles (≤6 concurrent, live progress table)
  Phase 3  Judge       → dedup → 4 gates → severity × confidence
  Phase 4  Prove       → PoC builder per finding (Go test / Foundry), fresh refuter verifies
  Phase 5  Critique    → coverage critic finds unexamined ledger units → optional extra wave
  Phase 6  Report      → deterministic assembler → REPORT.md + findings.json (schema-validated)
```

### Phase 0: Detect (deterministic)

`scripts/detect` reads `go.mod`, the file extensions, `foundry.toml` / `hardhat.config.*`, `Nargo.toml` and `*.circom`. It outputs `stack.json`.

The skill uses `stack.json` to route:

- gnark circuits go to the native engine.
- `.circom` goes to the zkSecurity `circom-auditor` if installed. Otherwise it gets a reduced generic-ZK pass.
- Solidity is always covered by our integration lenses, which also delegate to companions.

It flags the **gnark version** against the advisory table, e.g. "< v0.16.4: GHSA-7fx8 affects ECDSA/P256, keys must be regenerated". That alone is often a finding.

### Phase 1: Recon (`gnark-inventory`, a small Go tool shipped with the plugin)

The tool uses `go/packages` and `go/ast` because the target already has Go. It builds `go run` on first use and produces:

- **Circuits.** Every type with `Define(frontend.API) error`, its witness struct, and fields tagged `gnark:",public"` in **public-witness order**, including the flattening order of slices and arrays.
- **Hint inventory.** Every `NewHint` / `RegisterHint` call site and hint function, its output variables, and whether each output later reaches an `Assert*`, `ToBinary`, `rangecheck` or recomposition. This is a heuristic taint pass; anything not reached is pre-flagged.
- **Footgun hits.**
  - `DivUnchecked`
  - `bits.OmitModulusCheck`
  - `WithUnconstrainedOutputs`/`Inputs`
  - `api.Cmp`/`AssertIsLessOrEqual` on unbounded operands
  - `Lookup2` / `selector.Mux` / manual `flag*(a-b)` muxes
  - Go `if` on witness-derived values
  - `emulated.ValueOf` inputs without width checks
  - `ValueOfVerifyingKey` (VK as a witness)
  - `groth16.Setup` / `unsafekzg` outside tests
  - `api.Commit` with a Groth16 backend
- **Backend and export.** groth16 or plonk, the curve, `ExportSolidity`, and `WithProverTargetSolidityVerifier`. It also checks whether the generated `Verifier.sol` in the repo matches what the current circuit would emit, by compiling and diffing (deep profile only).
- **Contract side.** It greps and parses `verifyProof` / `verify` call sites. It maps each `uint256[] input` index to its source expression, and records nullifier and root storage.

Recon writes:

- **`system-map.md`** with actors, trust boundaries, and the prover → relayer → contract flow.
- **`binding-table.md`**: one row per public input, with columns `circuit field · index · contract source expr · range-checked? · bound to sender/chain/nonce?`. This table is the backbone of integration review.
- **`coverage-ledger.json`**: units are `circuit|gadget × constraint-class` and `contract-fn × integration-class`, validated by `scripts/validate-ledger`.
- **`source-*.md` bundles**, **sharded per circuit** so we don't duplicate the whole repo into every agent. Peripheral code (gnark std, vendored libraries) is listed but not inlined.

Deep profile adds `audit-context-building` (ToB) if it is installed, to build per-function dossiers. Its "assumption: nothing found" output is equivalent to "witness value never constrained".

### Phase 2: Hunt (agents)

Every agent bundle concatenates the following, in order:

1. Its source shard and the binding table.
2. The **senior-auditor SOP**, adapted for ZK. It asks: "What does this constraint *force*? What *other* witness satisfies it?"
3. Its lens file.
4. `shared-rules.md`, which defines the output schema, the read-only clause and the rule that `FINDING` needs `proof:` otherwise it is a `LEAD`.

**Circuit lenses (gnark)**

| # | Agent | Focus |
|---|---|---|
| C1 | `hint-soundness` | Every hint output is bound by recomposition, range or equality. Overrides of GHSA-3mvx and 7fx8 patterns. Prover-controlled outputs. |
| C2 | `range-decomposition` | `ToBinary` width and modulus aliasing, `cmp`/`api.Cmp` operand bounds, `rangecheck`, `uints`, byte packing, limb widths. |
| C3 | `field-arithmetic` | Wraparound, underflow read as a huge value, `Div` vs `DivUnchecked` (0/0), `Inverse(0)`, accumulator overflow, emulated `Reduce` non-canonicity, native vs emulated confusion. |
| C4 | `control-selector` | `Select`/`Lookup2`/`Mux` selector booleanity, flag-gated checks that collapse, Go control flow on witness values (compile-time vs constraint), loop bounds vs domain. |
| C5 | `crypto-gadgets` | Hash domain separation and length (MiMC length-extension, Poseidon2 arity, padding), Merkle leaf/index/root binding, signature canonicity (S < n), on-curve/subgroup/twist checks, `api.Commit` / Fiat-Shamir, recursion VK binding. |
| C6 | `spec-invariant` | Circuit vs spec and vs native Go reference (round trips, conservation, over-constraint/completeness). Delegates to `spec-to-code-compliance` if installed. |

**Integration lenses**

| # | Agent | Focus |
|---|---|---|
| I1 | `public-input-binding` | Order, count, encoding and flattening; inputs ≥ r and keccak-to-field truncation; values the contract relies on but the circuit never constrains; missing `msg.sender`/recipient/chainid/address/nonce, which enables front-running and cross-chain replay. |
| I2 | `verifier-contract` | Generated-verifier version (Last Challenge, commitment support), VK provenance and drift, upgradeable or admin-swappable verifier or VK, precompile return handling, Groth16 commitment PoK, custom verifier field checks. |
| I3 | `protocol-state` | Nullifier checked and stored atomically, root-history window, proof bytes used as an ID (malleability), signature-derived nullifiers (CVE-2025-57801), ordering and reentrancy around verify. |
| I4 | `prover-service` | Go code outside `Define`: witness construction mismatch, deserialisation DoS (CVE-2024-50354), key loading, dev setup in production, secrets in logs, gnark/gnark-crypto versions. Delegates `go.mod` checks to `supply-chain-risk-auditor`. |

**Cross-cutting agents**

| # | Agent | Focus |
|---|---|---|
| V1–Vn | `vector-scan` shards | Grind one catalog slice each (§5), using the mandatory classification gate. The number of shards scales with profile. |
| G1 | `numerical-gap` | range × field × invariant seams. |
| G2 | `binding-gap` | circuit × contract × protocol state. This is our flagship: "the circuit guarantees X; the contract assumes Y". |
| G3 | `composition-gap` | Gadget preconditions violated by the caller's wiring; sub-circuit handoffs. |
| A1 | `asymmetry` | hint ↔ constraint, native Go ↔ circuit, off-chain hash ↔ in-circuit hash, Groth16 ↔ PLONK paths, encode ↔ decode. |
| F1 | `first-principles` | Free-form. Extracts every assumption and tries to break it. Defaults to LEAD. |

**Profile sizing**

| Profile | Agents | Passes |
|---|---|---|
| quick | V shards + C1 + I1 + G2 | 1 |
| standard | All C, all I, V, G2, F1 | 1 |
| deep | Everything | 3 passes with a memory ledger |

At most 6 agents run concurrently, shown in a live progress table.

### Phase 3: Judge

**Dedup.** The `group_key` is `circuit|gadget|bug-class` for circuit findings and `contract|function|bug-class` for contract findings. Dedup never merges across circuits or functions. Distinct fixes are preserved as Option A/B. A completeness check ensures every raw `(unit)` survives.

**Gates**, adapted from zkSecurity and pashov:

1. **Executes.** The bad witness satisfies the constraints. Only a quoted constraint on the path can refute this; "the honest prover wouldn't" does not.
2. **Reachable.** A malicious prover or caller can produce the bad witness.
3. **Unprivileged.** If only the setup party or an admin can trigger it, DEMOTE, unless an amplifier is named.
4. **Impact.** Funds, forged state, a permanently bricked flow, or a meaningful privacy leak.

**Two axes.** We split zkSecurity's single score into two:

- **Severity**: Critical through Info, by impact × likelihood, capped at impact.
- **Confidence**: 0–100, using the deduction scheme.

**Verdicts** use Cloudflare's schema:

- `confirmed`
- `needs_validation`, with blockers. Examples: "which VK is deployed?", "was the ceremony honest?", "which gnark version runs in production?"
- `rejected`, which is kept so a later run does not re-raise it.

**Rationalizations to Reject** is a table in the skill. Examples:

- "The test suite passes." Tests only run the honest witness.
- "The hint computes it correctly." The prover chooses hint outputs.
- "The frontend validates it."
- "Only our relayer submits proofs."
- "gnark std is audited." See GHSA-3mvx.

### Phase 4: Prove (the differentiator)

For each `confirmed` circuit soundness finding, the `poc-builder` agent writes a Go test in a **scratch worktree**. The test:

- builds a malicious assignment, or overrides the hint with `solver.OverrideHint(id, evil)` via `test.WithSolverOpts`;
- asserts that `test.IsSolved` / prove + verify **succeeds** on a statement that should be false;
- includes a control case: the honest witness for the same statement must still pass, and a deliberately broken witness must be rejected for the *right* reason.

The skill runs it with `go test -run PoC ./...` under a sandbox: no network, a time limit, and writes only to scratch. The result sets `evidence: POC` or `ANALYSIS`.

Contract-side findings get a Foundry test with a mock or real verifier when `forge` is present.

A **fresh refuter** gets the finding and the PoC, starts from `refuted: true`, and must re-derive the bug from source. This uses ToB `fp-check` if installed and our embedded gate prompt otherwise. Any PoC that does not compile or does not demonstrate the bug downgrades the finding to `ANALYSIS`, and it may also lower its confidence.

### Phase 5: Critique

A coverage critic reads the ledger and the agent outputs. It returns the `missing_units` (for example "hint `divHint` never analysed", or "public input #3 has no binding row"). Standard and deep profiles run one extra targeted wave. Deep also runs a final-clean critic.

### Phase 6: Report

`scripts/assemble` is deterministic (Go or Node, zero dependencies). It turns `findings.json` and the ledger into `REPORT.md`. The report has these sections:

1. Scope, profile, stack and versions.
2. Posture summary.
3. Findings table (severity, confidence, evidence, detected-by).
4. Per-finding detail, with a constraint snippet, attack witness, PoC path and fix diff.
5. Leads.
6. Needs validation.
7. Hardening notes.
8. Coverage stats.

Report language follows the STE-style terse rules. A "verified clean" claim is never allowed.

---

## 5. Knowledge base (`references/`)

- **`attack-vectors/`**: a catalog organised by **code shape** (the construct you grep for). Each entry has `D:` (description), `FP:` (when it's not a bug), `Source:` (a mandatory GHSA, CVE or audit link), `Seed:` (inventory or Semgrep pattern id) and `PoC:` (the template to use). Initial slices:
  - `hints.md`
  - `range-bits.md`
  - `field-arith.md` (native and emulated)
  - `selector-control.md`
  - `hash-merkle.md`
  - `curves-signatures.md`
  - `commitments-recursion.md`
  - `public-inputs.md`
  - `verifier-contracts.md`
  - `protocol-state.md`
  - `prover-service.md`
  - `generic-zk.md`: zkSecurity's H1–H16, C*, D*, E* rewritten for gnark, with attribution.

  The target is about 80 vectors at v1. Seed sources:
  - the 11 GHSA-3mvx issues
  - the other 10 gnark advisories
  - the 12 zkSecurity gnark-std findings
  - the Least Authority, OpenZeppelin, Zellic and Veridise gnark reports
  - the 0xPARC tracker
  - the SoK taxonomy

  We follow the rule zkSecurity states but doesn't apply: **no vector without a real source.**
- **`gnark-versions.md`**: an advisory → affected range → impact → required action table, which Phase 0 consumes.
- **`gnark-api-footguns.md`**: the API contract of each std gadget, i.e. what it constrains and what the caller must still do.
- **`judging.md`, `severity.md`, `shared-rules.md`, `senior-auditor-sop.md`, `report-format.md`, `rationalizations.md`.**
- **`semgrep/gnark.yaml`**: test-first rules with `# ruleid:` and `# ok:` cases for the footguns above. They are optional, since the Go inventory tool is the primary detector, and they can also feed ToB `variant-analysis`.

---

## 6. Bringing in other skills

**Principle.** Delegate when a companion is installed, fall back to our embedded minimum when it isn't, and never install anything silently. `/zk-audit:setup` and the Phase 0 banner show the state of each companion, for example `✔ fp-check  ✖ circom-auditor (install: …)`.

| Need | Companion (if installed) | Embedded fallback |
|---|---|---|
| `.circom` circuits in scope | `zksecurity/zk-skills` `circom-auditor` | A generic-ZK vector subset applied to the Circom source |
| Broad Solidity bugs beyond ZK integration | `pashov/skills` `solidity-auditor`, plus `x-ray` for a threat model | I1–I3 cover the integration surface only; the report says so. |
| Per-function context dossier | ToB `audit-context-building` | Our recon |
| Circuit vs spec / paper | ToB `spec-to-code-compliance` | C6 lens |
| False-positive verification | ToB `fp-check` (plus `vulnerability-triage-brocards`) | Embedded refuter prompt |
| Variants after a finding | ToB `variant-analysis` | Grep the inventory for the same shape |
| Go and Solidity static analysis | ToB `static-analysis` (semgrep/CodeQL), `building-secure-contracts` (Slither) | Skip, and note it under coverage |
| `go.mod` / dependency risk | ToB `supply-chain-risk-auditor` | Our `gnark-versions.md` check |
| PR review | ToB `differential-review`, `trailmark` review gate | `/zk-audit diff` |
| Property and mutation testing | ToB `property-based-testing`, `mutation-testing` | Deep profile emits suggested oracle tests (native Go == circuit) and constraint-deletion mutants |
| Continuous / closed-engine second opinion | `zkao` CLI (paid, needs a token) | Not applicable. It is only offered and never run without consent. |

Delegated results come back as records in our `findings.json` schema, with `detected_by: <companion>`, so dedup and the report treat them uniformly.

---

## 7. Repository layout

```
zk-audit/
├─ .claude-plugin/marketplace.json
├─ plugins/zk-audit/
│  ├─ .claude-plugin/plugin.json
│  ├─ skills/zk-audit/
│  │  ├─ SKILL.md                     # <500 lines: modes, routing, orchestration turns
│  │  └─ references/                  # one level deep (see §5) + orchestration.md + agents/*.md
│  ├─ commands/{setup,diff,recon}.md
│  ├─ agents/                         # lens agents with tools: allowlists (read-only), poc-builder (scratch write)
│  ├─ tools/gnark-inventory/           # Go module: detect + inventory + verifier diff
│  ├─ scripts/{build-context,assemble,validate-ledger,validate-findings}  # zero-dep
│  ├─ schemas/{findings,ledger,stack}.schema.json
│  └─ evals/
├─ docs/{research.md, design-notes.md}
├─ NOTICE                             # upstream MIT attributions: zkSecurity, pashov, Cloudflare
│                                    # no LICENSE file: unlicensed for now (§10 Q1)
└─ Makefile / CI                      # lint, tool tests, schema tests, plugin metadata validation
```

---

## 8. Evaluation

We cannot reuse zkbugs as-is, because it has only one gnark entry. We will build our own corpus.

1. **Advisory replays.** Pin gnark to each vulnerable tag and audit the affected std package, with answer keys stripped. Covers CVE-2023-44378, GHSA-3mvx (selected issues), 7fx8, fwf3, CVE-2025-57801 and 45039.
2. **Planted fixtures.** About 25 small gnark circuits, each with one bug (unbound hint, `DivUnchecked` 0/0, `OmitModulusCheck`, non-boolean selector, Merkle leaf not bound, VK as witness, …). Each comes with a matching Solidity integration fixture (Foundry) for I1–I3 bugs: input order swapped, missing nullifier store, proof-hash nullifier, no `msg.sender` binding.
3. **All-safe panel.** About 10 correct circuits and integrations. Any finding on these counts as a false positive.
4. **Real-world sets.** Selected audited gnark projects (semaphore-mtb, gnark-plonky2-verifier) at their pre-fix commits, where the reports are public.
5. **Negative-trigger cases.** "Explain this circuit" or "fix this test" must not start a full audit.

**Metrics:**

- recall
- precision
- PoC success rate
- severity agreement
- cost and time per profile
- Δ against a no-plugin baseline

Each case runs 3 times so we can measure variance. We use the ToB `case.yaml` + graders format, so evals run under `claude plugin eval`.

---

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M0 | Repo renamed; plugin skeleton, marketplace, NOTICE, CI. No LICENSE yet (§10 Q1). | `/plugin install` works and `/zk-audit` prints its banner and stack detection. |
| M1 | `gnark-inventory` tool, `stack.json`, `binding-table.md`, ledger, context sharding. | It runs on 3 real gnark repos with correct public-input order and hint inventory, and has unit tests. |
| M2 | Knowledge base: about 80 sourced vectors, version table, footgun reference, rationalizations. | Every vector has a `Source:` and the version table covers all advisories. |
| M3 | Agents, orchestration, judging, deterministic report: **quick and standard profiles**. | The planted-fixture recall baseline is recorded. |
| M4 | PoC builder + sandboxed runner + refuter. | ≥70% of confirmed circuit findings on fixtures carry a working `POC`. |
| M5 | Integration lenses with Foundry PoCs; companion detection and `/zk-audit:setup`. | Integration fixtures pass; works with and without companions. |
| M6 | Eval harness and corpus (§8); tune lenses against the results. | Recall and precision reported, with Δ against baseline. |
| M7 | `diff` mode, `--loop` memory, deep profile critics, zkao bridge. | — |
| Later | Native engines for Noir and Halo2; Lean hand-off for gadget lemmas. | — |

---

## 10. Open questions for you

1. **License.** Unlicensed for now; the decision is deferred and there is no LICENSE file. `NOTICE` keeps the upstream MIT attributions (zkSecurity, pashov, Cloudflare) that adapted files require. Whatever license is chosen, we keep *delegating* to Trail of Bits skills rather than copying their CC BY-SA 4.0 text, which would force CC BY-SA on us.
2. **Runtimes.** Claude Code only, or also Codex like zkSecurity? Recommendation: Claude Code first, but keep the prompts runtime-neutral.
3. **PoC execution.** Is running `go test` and `forge test` on audited code acceptable by default in standard mode, or deep mode only? Recommendation: default on in a scratch worktree, with `--no-poc` to turn it off.
4. **Real-world eval targets.** Do you have private gnark codebases with known findings we can use as held-out benchmarks?
5. **zkao bridge.** Worth integrating in v1, or leave it for later?
