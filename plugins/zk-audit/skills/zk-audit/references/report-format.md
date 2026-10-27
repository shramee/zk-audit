# Report format

<!-- Structure adapted from zkSecurity zk-skills circom-auditor report-formatting.md (MIT, (c) 2026 zkSecurity) and pashov skills solidity-auditor report-formatting.md and report-language.md (MIT, (c) 2024 AI Skills Contributors). -->

`REPORT.md` is rendered from `findings.json`, `coverage-ledger.json`,
`stack.json` and `binding-table.md` after both JSON files validate. Rendering
copies; it does not re-judge, re-rank or re-word findings. (A later milestone
adds a deterministic `assemble` subcommand that writes this file. Until then
the orchestrator renders it by following this file exactly.)

Path: `~/.zk-audit/<repo>/<run-id>/REPORT.md`. With `--file-output`, the same
file is also written to `<repo>/zk-audit-report-<run-id>.md`.

## Language

- Titles, descriptions and lead text are short, active, present tense. Name
  the actor: "Any prover sets the remainder…". One idea per sentence, at most 25
  words.
- Never write "verified clean", "secure", "no vulnerabilities" or "fully
  audited". Write what was examined and what was found.
- Identifiers, `bug_class` labels, code and diffs are copied exactly.

## Structure

````markdown
# ZK security review — <repo> @ <short commit>

## 1. Scope

| | |
|---|---|
| Profile | standard |
| Run | 20261027-101500 |
| Commit | <sha> |
| Files reviewed | `circuit/transfer.go` · `circuit/sig.go` · `contracts/Pool.sol` |
| Stack | gnark v0.14.0 (advisories: 3) · groth16 · bn254 · solidity · foundry |
| Companions | ✔ fp-check · ✖ circom-auditor |
| Agents | C1–C6, I1–I4, V-hints, V-range, …, G2, F1 |
| Out of scope | <what and why> |

## 2. Posture

Three to six sentences: the main trust assumptions (setup, VK provenance, who
submits proofs), the strongest and weakest areas, and the single most important
action. No marketing.

## 3. Findings

| # | Title | Severity | Confidence | Evidence | Detected by |
|---|---|---|---|---|---|
| 1 | Remainder hint output is never range-bound | high | 90 | POC | C1, V-hints |

## 4. Finding details

### 1. <Title>

`TransferCircuit.Define` · `circuit/transfer.go:61-69` · severity **high** · confidence 90 · evidence **POC** · detected by C1, V-hints · vectors V-H3

**Description.** <one sentence from the record>

**Constraint.**

```go
<the offending lines, verbatim>
```

**Attack witness.** <the record's proof field>

**Impact.** <impact>

**PoC.** `pocs/<file>` — `go test -run PoC_1 ./circuit` → demonstrated.

**Fix** (Option A — <label>)

```diff
<verbatim diff>
```

**Refuter.** exploitable — <one paragraph>

## 5. Leads

Trails worth manual work. No severity, no fix.

- **<title>** — `scope` · `file:line` · detected by … — <description>. Unverified: <unverified>.

## 6. Needs validation

| Item | Blockers | How to validate |
|---|---|---|

## 7. Hardening notes

Optional, short: hygiene that is not a vulnerability (stale verifier file in the
repo, no public-input-order test, `api.Println` in a circuit).

## 8. Coverage

| Units | planned | covered | candidate | deferred | blocked | not applicable | out of scope |
|---|---|---|---|---|---|---|---|

- Ledger units not covered, with reasons (copied from the ledger).
- Rejected candidates: N (kept in `findings.json`).
- Companions not available and what that leaves uncovered.
- Load mode of the inventory (`types` / `syntax` / `mixed`) and its errors.

> This review is a time-boxed, best-effort search for bugs by an automated
> agent. It is not a guarantee of security. Absence of a finding is not
> evidence of absence of bugs.
````

## Rules

- Findings sorted by severity, then confidence, then title.
- A confirmed finding below confidence 80 prints description, constraint,
  witness and impact, but no fix block unless one exists.
- Keep a finding the refuter marked `not_exploitable` only if a gate still
  passed. Show both views.
- KNOWN / NEW tags (with `--loop`) go after the title: `[KNOWN 2/3]`.
- The coverage section is mandatory, even with zero findings.
