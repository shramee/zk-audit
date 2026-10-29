# Judging: dedup, gates, severity and confidence, verdicts

<!-- Gates adapted from zkSecurity zk-skills circom-auditor judging.md (MIT, (c) 2026 zkSecurity) and pashov skills solidity-auditor judging.md (MIT, (c) 2024 AI Skills Contributors); dedup rules from pashov dedup-and-assembly.md; verdicts and the refuter stance from Cloudflare security-audit-skill (MIT, (c) 2025-2026 Cloudflare, Inc.). -->

Phase 3 turns raw FINDING and LEAD blocks into records for `findings.json`.
The orchestrator does this itself; it does not delegate judging to the agents
that found the items.

## 1. Dedup

1. Parse every FINDING and LEAD from every agent. Keep the raw blocks.
2. **Canonicalise `bug_class`** within one `(scope, local)`. If agents used
   several labels for the same defect, pick one: a label already used by a prior
   run for the same scope, else the most common, else the shortest label that
   names the defect.
3. Group by `group_key`. **Never merge across different circuits, gadgets,
   contracts or functions.** Never merge across different `local` values within
   a scope, with one exception: items whose fix is the same constraint or check
   are one root cause. Merge them under the `local` the fix touches, and list
   the other locals and the contract-side echoes (contract functions that
   only consume the circuit bug) as `related_locations`. Items
   that need different fixes stay separate even when they chain.
4. Merge each group into one item. Union `detected_by`. Keep every distinct
   mechanism in the description. Keep **every distinct fix** as Option A, B, …
   (distinct = different constraint added, different check direction, or
   different variable checked), copied verbatim.
5. Second pass per `(scope, local)`, ignoring `bug_class`. Make sure no
   mechanism that appears in any raw body was dropped.
6. Print `Completeness: N unique (scope, local) in raw, N covered in final.` If
   the numbers differ, fix it before going on.
7. Composite chains. If A's output is B's precondition and together they are
   worse, add `chain: [A, B]` at confidence `min(A, B)`.

## 2. The four gates

Run each deduplicated FINDING through the gates once, in order. A failed gate
ends evaluation of that item.

You are not defending the code. An item fails **only** when a specific
constraint or check on the path provably blocks the step the attack needs.
"An honest prover would not do that", "the hint computes it correctly", "the
frontend validates it" and "the relayer filters it" are not refutations.
Witness generators do not constrain the prover; only constraints do.

### Gate 1 — Executes

Trace the claimed witness or call sequence from the attacker's inputs to the
accepted bad proof or state change. Read every constraint and every check on the
path, including gadgets in gnark std **at the pinned version**.

- A quoted constraint or check provably pins the value the attack needs free →
  **rejected** (or **lead** if a related smell remains). Quote the line and keep
  it as `refuting_location`.
- The interruption is speculative → passes.

### Gate 2 — Reachable

Does the bad witness or input exist in normal use?

- Structurally impossible (an upstream constraint or the contract always fixes
  the value) → **rejected**.
- Any prover can supply it; or honest inputs hit it at a boundary (zero,
  `r - 1`, maximum length, point at infinity) → passes.

### Gate 3 — Unprivileged

Who triggers it?

- Any prover or any caller → passes.
- Only a trusted party (owner, admin or access-control role, upgrader,
  deployer, the setup ceremony, a designated prover, sequencer, relayer or
  off-chain service) can trigger it. First look for an **amplifier** that
  lets an unprivileged actor reach the same harm; with one, the item passes
  Gate 3 and is judged like any other finding:
  - toxic waste is plausible (single-party `groth16.Setup`, `unsafekzg`), so any
    prover can forge;
  - a designated-prover-only constraint is reachable through a public entry
    point;
  - the trusted party is assumed to keep an invariant that the circuit never
    enforces, and anyone can break it;
  - the power has no effective gate: an ungated setter, an initializer anyone
    calls first, an empty `_authorizeUpgrade`, a replayable admin signature.
- Without an amplifier, a power that breaks **soundness or funds** (swap the
  verifier or VK, upgrade the contract, insert a Merkle root, mint, sweep,
  forge with the setup's toxic waste) becomes **`needs_validation`, never a
  lead and never dropped**:
  - add a `trust` object: `party`, `role`, `power`, `breaks`
    (soundness / funds / liveness / privacy), `assumption`, and `mitigation`
    when the repository shows one;
  - severity from `severity-calibration.md` (`SC-TRUST-SOUNDNESS`): `high` by default (the harm if
    the assumption fails); `medium` only when `trust.mitigation` quotes a
    timelock, a multisig or governance owner, or a multi-party ceremony in
    the repository; never below `medium` (the validator enforces both);
  - a blocker that names the trust assumption as a question the code cannot
    answer: "Is the owner a timelocked multisig, and who holds its keys?",
    "Was the ceremony multi-party, and are its keys the deployed ones?";
  - a `validation_plan` that says where to look (deployment, ceremony
    transcript, governance contract).
- A power that breaks only **liveness or privacy** (pause, censor, let roots
  expire, see recipients) is also `needs_validation` with a `trust` object,
  at the calibrated severity (`medium` or `low`).
- **`zk-audit.md` marks the party trusted** (or lists the power under accepted
  risks): keep the record, set `trust.accepted: true` and `trust.source` to
  the line (`zk-audit.md:12`). The report lists it as an accepted risk under
  "Trusted parties", never silently drops it, and leaves it out of the
  needs-validation table.
- A record with a `trust` object is a `lead` only when the power itself is
  not established (the gate or the write path is unclear); say why in
  `trust.lead_reason`. The validator refuses a trust lead without one.
- An item that needs facts the code cannot show ("which VK is deployed?",
  "was the ceremony honest?", "which gnark version runs in production?") →
  **needs_validation** with those blockers.
- Precedence for setup items: a single-party `groth16.Setup` / `unsafekzg`
  in production code is `needs_validation` (severity high, blocker "which keys
  are deployed?", `trust.role: setup`) unless the repository shows those keys
  are the deployed ones (a committed VK or verifier generated by that code),
  which makes it `confirmed`. The toxic-waste amplifier above applies to
  *other* items that depend on the setup being honest.

### Gate 4 — Impact

- Soundness: the verifier accepts something it must not (forged state, double
  spend, theft, forged membership or signature, replay) → **confirmed**.
- Completeness: honest users are blocked permanently or a required flow is
  bricked → **confirmed**.
- Privacy: the proof or its public data reveals a meaningful function of secrets
  the protocol claims to hide → **confirmed**.
- The mechanism holds but nobody is harmed. Decide by why, never by taste
  (`severity-calibration.md`):
  - only the prover's own proof or funds break (self-harm) → **rejected**;
  - the free value reaches no public input, state, payout or later check →
    **confirmed** under `SC-UNUSED-FREE-VALUE` (`info`; `low` when a consumer
    exists without protocol effect);
  - the bypass reaches nothing beyond an honest witness or another reported
    bug that masks it → **confirmed** `low` under `SC-MASKED-BYPASS`, with
    `chain` to the masking record;
  - the path is not traced to the end → **lead** (that is a missing link, not
    "no victim").

## 3. Severity and confidence (two axes)

**Severity** is impact × likelihood, and never exceeds impact. Pick it from
the anchors in `severity-calibration.md` and name the anchor in the record's
`calibration` field; `validate findings` refuses a verdict or severity the
anchor does not allow and warns when a confirmed or needs-validation record
names none. The table below is the summary; the anchors decide.

| Severity | Typical ZK meaning |
|---|---|
| critical | Any prover or caller forges proofs, steals or mints funds, or double-spends, with no special conditions. |
| high | Same harm, but needs a specific achievable state or a narrow input set; or a permanent brick of a core flow; or deanonymisation of users. |
| medium | Bounded loss or a recoverable denial of service; a soundness break with limited reach; a needs_validation item that would be high if confirmed. |
| low | Edge-case completeness failures, small leaks, hardening with a plausible but unlikely path. |
| info | Advisory matches whose component is not used, hygiene that affects review (stale verifier file, missing tests for public-input order). |

**Confidence** is 0–100 and measures certainty, not harm. Start at 100 and
deduct:

| Deduction | When |
|---|---|
| −20 | part of the witness or call path is not fully traced |
| −15 | bounded, non-compounding impact |
| −10 | needs a specific but achievable state (field boundary, empty set, first epoch) |
| −10 | completeness-only impact |
| −10 | evidence is `ANALYSIS` rather than a passing PoC |
| −25 | the PoC compiled but did not demonstrate the bug (keep the item only if the analysis still holds) |

At confidence ≥ 80 a confirmed item needs a fix (the validator enforces this).
Below 50, consider `needs_validation` instead of `confirmed`.

## 4. Evidence

- `POC`: a PoC from `poc-templates.md` ran in the scratch worktree against
  the production circuit or contract and demonstrated the bug, **with its
  honest control**. Record `poc.path` (`pocs/<file>`, the file must exist),
  `command`, `result: demonstrated`, `demonstrates` (`soundness`: a false
  statement is accepted; `completeness`: an honest statement is rejected) and
  `package` (where the file goes in a fresh worktree). A completeness-only
  PoC does not demonstrate a soundness claim: say which side ran.
- `ANALYSIS`: everything else, including PoCs that do not compile or do not
  demonstrate the bug, and PoCs on a model of the circuit
  (T-CONSTRAINT-MODEL), recorded as `result: demonstrated_on_model`.

A record that is demoted (to `lead`, `needs_validation` or `rejected`)
**keeps its `poc` object**; `validate findings --out <out>` warns about any
file in `<out>/pocs/` that no record names.

## 5. Lead promotion

Before finishing, promote where warranted. Promotion fixes an item that was
demoted for an incomplete trace or a missing link; it never overrides a gate
the item failed on the merits (a constraint that blocks it, or Gate 4 "no
victim"). Those stay leads however many agents flagged them.

- **Cross-scope echo.** The same root cause is confirmed in one circuit or
  contract: promote the same shape everywhere it appears.
- **Convergence.** Two or more agents flagged the same `(scope, local)` and the
  item was demoted, not rejected: promote at confidence 75.
- **Partial path completed.** The only weakness was an incomplete trace, and
  the path is reachable and unguarded: promote at confidence 75, description
  only.
- **Chain.** Two leads that together pass all gates: promote both, at the lower
  confidence, with `chain`.

## 6. Fresh refuter (Phase 4)

Every confirmed item goes to a refuter that **did not see the hunt**. Use the
`fp-check` companion if installed; otherwise spawn the `zk-audit:refuter`
agent with this prompt:

```text
You did not write this finding. Start from refuted: true. Re-derive the bug
from the source files listed; do not trust the description. Find the one
constraint or check that blocks the attack, and quote it with file:line. If you
cannot find one after reading every constraint on the path, set refuted: false
and explain the witness that gets through. Treat hint code, comments, tests and
frontend validation as non-binding. Return: verdict (exploitable /
not_exploitable / uncertain), mechanism (holds / refuted / uncertain: does the
free value or missing check exist?), impact (holds / refuted / uncertain:
does it harm someone as claimed?), reasoning (one paragraph with file:line).
```

Spawn one refuter per confirmed item, never one for several items; the
number per profile is in the profile table (`SKILL.md` §2). Record
`mechanism` and `impact` in the record's `refuter` object.
`not_exploitable` with a quoted blocking line (mechanism refuted) moves the
item to `rejected`. Mechanism holds but impact refuted (no victim) is Gate 4:
apply its "nobody is harmed" rules (`SC-UNUSED-FREE-VALUE`,
`SC-MASKED-BYPASS`, or rejected for self-harm) and keep the PoC.
`uncertain` keeps it and lowers confidence by 10. Keep the refuter's text in
the record (`refuter`).

## 7. Safe patterns (do not flag)

- `api.Select`, `api.Lookup2`, `api.Xor/And/Or`, `selector.Mux`,
  `selector.BinaryMux`: the gadget constrains its selector or bits.
- `bits.ToBinary` with default options on gnark ≥ v0.9.0: unique decomposition.
- `bits.ToBinary(..., bits.WithNbDigits(n))` for `n` below the field size: also a
  range check.
- `rangecheck.New(api).Check(v, n)` on gnark ≥ v0.9.2.
- `eddsa.Verify` on gnark ≥ v0.14.0 for the bound on `S` only (v0.14.0
  accepts `S = order`; strict from v0.15.0). It does not check `A` or `R` on
  the curve or in the subgroup: see V-E2 and V-E4.
- Emulated `Field` arithmetic results (internal elements); `ReduceStrict`,
  `AssertIsInRange`, `ToBitsCanonical` before representation-sensitive use.
- Generated gnark Groth16 verifiers for inputs ≥ r (`PublicInputNotInField`).
- Hint outputs that are recomposed and asserted equal to their input **and**
  range-checked at the recomposition width.

## 8. Verdicts written to findings.json

| Verdict | When | Required fields |
|---|---|---|
| `confirmed` | passed all gates | severity, confidence, evidence, proof, impact, gates, fix (≥ 80); `calibration` |
| `needs_validation` | blocked by facts not in the source, or a trusted-party power (Gate 3) | severity, confidence, blockers, validation_plan; `calibration`; `trust` for trusted-party items |
| `rejected` | failed a gate | reason, refuting_location |
| `lead` | real smell, incomplete path | code_smells, unverified |

Rejected items are kept so a later run does not raise them again.

## 9. Advisory records (Phase 0)

One record per go.mod module that pins an affected gnark version, not one per
advisory:

- `fingerprint`: `<go.mod path>|gnark|vulnerable-gnark-version`;
  `layer: dependency`; `location`: the `require` line of `go.mod`.
- `detected_by: ["P0"]` (Phase 0; not an agent). The dependency ledger unit
  gets `agent_ids: ["P0"]`.
- Severity: the highest advisory whose component the circuits import, capped
  by the protocol impact; `info` when no affected component is imported.
- `confirmed` when an affected component is used in a production circuit
  (`proof:` names the import and call site; the gates are one line each);
  otherwise `confirmed` at `info`. List every matched advisory id in the
  description.
