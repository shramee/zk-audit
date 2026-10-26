# Research notes: prior art for a ZK / gnark audit skill

Snapshot taken 2026-10-25. Sources were read, not executed. Every claim about gnark APIs was checked against gnark master (`0be5c2ff`, latest release v0.16.4).

## 1. zkao (zkSecurity)

zkao is zkSecurity's **commercial, closed-engine** service that audits cryptography and ZK code with AI agents.

- Site: https://zkao.io/
- Docs: https://docs.zkao.io/llms-full.txt
- Agent skill: https://docs.zkao.io/skill.md
- Launch post: https://blog.zksecurity.xyz/posts/zkao-launch/ (2026-02)
- Open-source clients only (MIT): `zksecurity/zkao-sdk` (TypeScript SDK, `@zksecurity/zkao-cli`, a `skills/zkao/SKILL.md`) and `zksecurity/zkao-action`.

How it works:

- **Free repo map.** It splits the repository into audit areas and lists open threat-model questions.
- **Scan presets.**
  - `quick-look`
  - `deep-audit`
  - `diff` (base..head, computed from the merge base)
  - Continuous Testing (daily, resumable)
  - Dependency Watch
  - Regression Check
- **Techniques.** Tracing untrusted inputs, spec-to-code diffing, and machine-checked models.
- **Findings.** Results are deduplicated and verified. Each finding carries:
  - `triageStatus`: CONFIRMED, FALSE_POSITIVE or DUPLICATE.
  - `confirmationEvidence`: `POC` or `ANALYSIS`.
  - Severity: CRITICAL through INFO.
- **Guidance layers.**
  - A committed `zkao.md` in the repo root holds scope, attacker model, trusted components, properties, severity expectations and accepted risks.
  - Guidance stored on the repo.
  - Per-scan guidance.
- **Thesis.** "A single scan is a coin flip," so it re-scans continuously and dedups across runs.
- **Language and framework support.**
  - It launched for Circom only.
  - The site now lists Rust, Go, Solidity, Circom, Noir and Lean.
  - Frameworks include **gnark**, Halo2, Plonky3, arkworks and zkVMs.
- **Track record.** It found real gnark bugs. GHSA-3mvx-pp85-pm65 (Critical, 2026-08) credits "zkSecurity and zkao".

**What we take from it:**

- A committed guidance file (our `zk-audit.md`).
- Free recon before paid or expensive hunting.
- Diff and continuous modes.
- PoC-vs-analysis evidence on every finding.
- Cross-run dedup.
- An optional bridge to the zkao CLI for users who have credits.

## 2. zksecurity/zk-skills: `circom-auditor` (MIT)

The closest relative to what we want. It is a Claude Code and Codex skill for Circom only.

**Workflow:**

- `scripts/build_audit_context.py` builds the scope.
  - In-scope files plus an include graph.
  - Vendored libraries are treated as *peripheral*.
  - It writes a single `source.md`.
- 17 agent **bundles**, each `source.md + senior-auditor-sop + lens + shared-rules`.
  - Agents get a file path and a line count, never inlined source.
  - At most 6 run concurrently, shown in a live `Agent Progress` table.
- The agents fall into four groups:
  - 6 vector-scan shards. Each grinds one catalog slice behind a mandatory `Skip/Drop/Investigate` classification gate.
  - 8 single-lens specialists.
  - 3 gap hunters, which drop anything a single lens could find.
  - First-principles and free-flow passes.
- Dedup, then 4 judging gates:
  1. Attack executes against the constraints.
  2. Reachable by a malicious prover.
  3. Unprivileged trigger.
  4. Impact.
- Then a fresh-context triager. A FINDING requires a concrete witness `proof:`, otherwise it is a LEAD.
- Evals: zkbugs reproducers with answer-key stripping and LLM-judged recall.

**Gaps we must fill:**

- It barely covers on-chain verifier and integration. Scope only collects `.circom` files.
- No tool-assisted PoC.
- No severity axis, only confidence.
- Recall-only evals with 3 benchmarks.
- Every bundle duplicates the full source, which costs too much on large repos.

**Transferability.** About 36 of its 48 vectors are generic ZK and can be rewritten for gnark. The Circom-only ones are L1, L3–L5, B6, B7 and A2.

## 3. pashov/skills (MIT)

`solidity-auditor` is a Turn-based orchestrator.

- One `AskUserQuestion` up front for model and pass count.
- 12 bundles in parallel: 9 lenses plus 3 gap hunters.
- A memory ledger (`.solidity-auditor/memory.tsv`) supports `--loop`, with KNOWN/NEW tags and "seen in k/N runs".
- A **shell-only report assembler**, so no findings are lost to context pressure.
- STE100 report language.
- The rule "a report must not overstate its coverage".

`x-ray` does pre-audit threat modeling.

- Entry-point scan as a hard gate.
- Invariant synthesis by guard lift plus a grep over every write site.
- Verdict tiers.

`fizz` generates fuzz suites and chains to x-ray via an acquisition protocol.

**Reusable ideas:**

- The senior-auditor SOP (Feynman, Socratic, Inversion).
- The asymmetry lens. Retarget it to the pairs hint↔constraint, prover↔verifier ordering, off-chain↔in-circuit hash, and Groth16↔PLONK.
- The gap-hunter seam pattern.
- Fix-option preservation.
- The read-only clause in every agent prompt. It was added after agents wrote PoCs into the audited repo.

## 4. cloudflare/security-audit-skill (MIT)

- **Two modes.** Guidance mode is the default. Full-audit mode runs only on explicit request.
- **Output location.** Output goes *outside* the target, to `~/security-audit-skill/<repo>/run-N`.
- **Profiles.** quick, standard and deep, with a budget that reserves critics and validation first.
- **Recon.** 4 recon agents produce `architecture.md` and a **coverage ledger** of deterministic units: surface × boundary × subsystem × attack class. A Node validator checks the ledger.
- **Hunting and critics.** Hunting waves are assigned ledger units. A coverage critic runs after each wave, then a final-clean critic.
- **Verification.** Every candidate goes to a verifier that didn't find it ("You did not write this candidate. Try to refute it"). Then a second independent record verification.
- **Verdicts.** `confirmed`, `needs_validation` (with exact blockers) and `rejected` (kept so it is not re-raised), enforced by a JSON schema and validator.
- **Rules worth adopting.**
  - "Defense-in-depth gaps are not vulnerabilities."
  - "Compare what A guarantees with what B assumes at every handoff."
- **Execution sandbox.** Scratch-only writes, no network.

**Mapping to ZK.** `needs_validation` fits ZK facts that can't be seen in source: which VK is deployed, ceremony provenance, and the production gnark version.

## 5. trailofbits/skills (CC BY-SA 4.0, so adapting text forces ShareAlike; delegating by name does not)

**Packaging.**

- `.claude-plugin/marketplace.json` plus `plugins/<name>/.claude-plugin/plugin.json`.
- Users install with `/plugin marketplace add`.
- Thin router SKILL.md files point to `workflows/*.js` fan-outs, which return schema-bound JSON records. Refuter agents start from `refuted: true`.

**Authoring rules worth following.**

- SKILL.md stays under 500 lines.
- References go one level deep.
- Every security skill has a "Rationalizations to Reject" table.
- "Ask for everything with severity, filter in a separate pass."
- "A checker that inspects zero items must fail."
- Evals use `case.yaml` plus graders, scored as Δ against a no-plugin baseline. Each eval set includes an all-safe panel and negative-trigger cases.

**Delegation targets (if installed):**

| Plugin | Use in a ZK audit |
|---|---|
| `audit-context-building` | Per-function context dossier. Its "nothing found" assumptions map to unconstrained witness values. |
| `spec-to-code-compliance` | Circuit vs paper/spec. Its verdicts implemented/partial/contradicted/stronger-than-spec/absent fit under- and over-constraint. |
| `variant-analysis` | After a finding, Go rules via semgrep/CodeQL. |
| `fp-check` | Gate-based true/false-positive verdict, with a Stop-hook enforcement pattern. |
| `static-analysis`, `semgrep-rule-creator` | Go hygiene, and shipping test-first gnark Semgrep rules. |
| `supply-chain-risk-auditor` | `go.mod` checks for gnark and gnark-crypto advisories. |
| `differential-review`, `trailmark` review gate | PR mode, e.g. a removed `Assert*` call. |
| `building-secure-contracts`, `entry-point-analyzer` | Verifier and caller contracts with Slither. |
| `property-based-testing`, `mutation-testing` | Oracle tests (native Go == circuit) and constraint-deletion mutants. |
| `vulnerability-triage-brocards` | First-pass filter before validation. |

ToB has no ZK audit content of its own. It has only `circomvent` (internal), a gnark-crypto mutation case study in `vector-forge`, and a Circom parser in trailmark.

## 6. gnark security knowledge base

### Advisories

| ID | Sev | Pattern | Fixed |
|---|---|---|---|
| GHSA-7fx8-hmgc-82jp | High | Fake-GLV scalar-mul hint result not checked on-curve, enabling ECDSA/P256 forgery. **Regenerate keys.** | v0.16.4 |
| GHSA-3mvx-pp85-pm65 | Critical | 11 std bugs, all "hint output consumed without binding/range constraint". Includes emulated carry not range-checked, unconstrained torus scale, GLV sub-scalars unbound, remainder vs runtime modulus, uints lookup key collision (SHA2/Keccak), Miller loop Q=0, comb top bit. | v0.16.2 |
| GHSA-fwf3-jmp7-gmrj | Mod | G2 subgroup/twist check computed but discarded (`IsOnTwist` vs `AssertIsOnTwist`). | >v0.15.0 |
| GHSA-95v9-hv42-pwrj / CVE-2025-57801 | High | EdDSA/ECDSA S not checked `< order`, so signatures are malleable and nullifiers derived from (R,S) can be double-spent. | v0.14 |
| GHSA-9fvj-xqr2-xwg8 | High | DoS in fake-GLV. | 2025 |
| GHSA-cph5-3pgr-c82g / CVE-2024-50354 | Mod | OOM when deserializing crafted VK or proof. | ≥0.11 |
| GHSA-q3hw-3gm4-w5cr / CVE-2024-45039 | Mod | Groth16 with more than one commitment is unsound. | v0.11.0 |
| GHSA-9xcg-3q8v-7fq6 / CVE-2024-45040 | Mod | Groth16 commitment to private witness breaks zero knowledge. | v0.11.0 |
| GHSA-rjjm-x32p-m3f7 | Low | rangecheck accepted values up to 16 bits too wide. | v0.9.2 |
| GHSA-7p92-x423-vwj6 | Crit | PLONK Solidity verifier "Last Challenge" forgery. | v0.9.1 |
| GHSA-498w-5j49-vqjg / CVE-2023-44378 | High | `Cmp`/full-width `ToBinary` accept the non-unique decomposition a vs a+r. | v0.9.0 |

### Audits worth mining for vectors

- **zkSecurity, gnark std (2024-05)**: https://reports.zksecurity.xyz/reports/consensys-gnark-std/
  - #00 MultiCommitter challenge can converge to 1.
  - #01 Partition function unsound.
  - #02 `uints.ValueOf` hint bytes never recomposed.
  - #03 Non-cryptographic `HashCode()` lets elements skip width constraints.
  - #04 Emulated `IsZero` condition flipped.
  - #05 MiMC length extension.
  - #06 `modSub` padding underflow.
  - #07 `Reduce` may return a value ≥ p.
  - #08 Native GLV decomposition checked mod the native field.
  - #09 Non-canonical NAF.
  - #0a `wrapped_hash` zero-padding collides across lengths.
  - #0b Emulated `Element` inputs are not width-constrained. This is a leaky abstraction and was marked won't fix.
- **Least Authority, gnark/Linea (2024)**: https://leastauthority.com/blog/gnark-cryptographic-library/
  - FFT generator missing from the transcript.
- **OpenZeppelin, Linea PLONK verifier and prover**:
  - https://www.openzeppelin.com/news/linea-verifier-audit-1
  - https://www.openzeppelin.com/news/linea-prover-audit
  - Last Challenge paper: https://eprint.iacr.org/2024/398
- **Zellic, gnark Universal Proof Aggregation**:
  - Public-input length check bypassed by wraparound at r−1.
- **Veridise, gnark-plonky2-verifier**: report available.
- **Least Authority, Worldcoin semaphore-mtb**: reviews from 2023 and 2024.

### gnark API footguns (verified in source)

**Hints**

- Outputs of `NewHint` / `solver.RegisterHint` are fully prover-controlled.
- `test.IsSolved` runs the honest hint, so it cannot detect under-constraint.
- To write a PoC, use `solver.OverrideHint` together with `test.WithSolverOpts`, or `test.WithInvalidAssignment` together with `assert.ProverFailed`.

**Division**

- `api.DivUnchecked(0,0)` leaves the output unconstrained.
- `Div` and `Inverse` on zero are unsatisfiable, which is a completeness issue.

**Bit decomposition**

- `bits.OmitModulusCheck()` allows the a / a+r alias.
- `bits.WithUnconstrainedOutputs()` and `WithUnconstrainedInputs()` turn off booleanity checks.

**Comparisons**

- `api.Cmp` and `AssertIsLessOrEqual` compare canonical values in [0, r). An underflowed value r−k therefore counts as huge.

**Emulated arithmetic**

- Emulated `Element` witnesses are not width-constrained.
- `Reduce` may return a value ≥ p. Use the canonical variants when canonicity matters.

**Merkle (`std/accumulator/merkle`)**

- It applies no domain separation.
- The leaf is `Path[0]` and must be bound to its preimage.
- Check that the root is public or otherwise bound.

**Hashes**

- MiMC is vulnerable to length extension. Use a domain tag.
- `FixedLengthSum` needs its length input bounded.

**Recursion**

- `ValueOfVerifyingKey` makes the VK a witness, which must be bound to a constant or public hash.
- `ValueOfVerifyingKeyFixed` embeds the VK as a constant instead.

**Public inputs**

- Only fields tagged `gnark:",public"` are public inputs.
- Public-witness order follows struct field order and must match the contract's input array.

**Groth16 Solidity verifier**

- It reverts with `PublicInputNotInField` on inputs ≥ r. Custom verifiers may not.
- Commitments need `WithProverTargetSolidityVerifier`.

**Setup**

- Using `groth16.Setup` or `test/unsafekzg` in production is a finding. Use the MPC setup or a PLONK SRS.

### Datasets and tools

- **zkbugs**: 140 entries, but only **1** is gnark (CVE-2023-44378). We need our own gnark benchmark corpus.
- **0xPARC zk-bug-tracker**: covers nullifier range checks, nondeterministic nullifiers and Semaphore input aliasing.
- **SoK** (Chaliasos et al., USENIX'24): 141 SNARK bugs classified into circuit, frontend, backend and integration layers.
- **Other tools.**
  - Frozen Heart (ToB 2022).
  - Circuzz (metamorphic fuzzer with gnark support).
  - Picus works on Circom and R1CS. Using it on gnark R1CS is unverified.
  - Reilabs `gnark-lean-extractor` exists but only supports gnark v0.9 and is stale.
- **No gnark linter or static analyzer exists.** The only gnark-capable automated auditor is zkao.

### Integration-layer issues

- **Groth16 malleability.** Never key nullifiers or replay protection on proof bytes.
- **Witness malleability.** A malleable witness, such as EdDSA S+n, breaks signature-derived nullifiers.
- **Public inputs ≥ r.** They alias on custom verifiers.
- **Nullifier handling.** The nullifier must be checked and stored atomically with verification.
- **Root history.** Roots must be checked against a root-history window.
- **Binding.** `msg.sender`, recipient, chainid, contract address and nonce/epoch must be in the statement.
- **VK drift.** A stale `Verifier.sol` after a circuit change, or a verifier or VK that an admin can swap.
- **Fiat-Shamir.** Transcripts that omit elements (Frozen Heart, Last Challenge), and hash-to-field mismatches between prover and on-chain verifier.
