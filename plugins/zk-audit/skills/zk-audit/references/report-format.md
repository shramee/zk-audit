# Report format

<!-- Structure adapted from zkSecurity zk-skills circom-auditor report-formatting.md (MIT, (c) 2026 zkSecurity) and pashov skills solidity-auditor report-formatting.md and report-language.md (MIT, (c) 2024 AI Skills Contributors). -->

`REPORT.md` is written by the deterministic assembler, never by hand:

```bash
{skill}/scripts/gnark-inventory assemble --out <out> --repo <repo>
```

It reads `findings.json`, `coverage-ledger.json`, `stack.json` and
`inventory.json` from `<out>`, validates them, and refuses invalid input (exit
1, no report). Rendering copies; it does not re-judge, re-rank or re-word
findings. Same inputs, same bytes.

Where each part comes from:

| Report part | Source |
|---|---|
| Scope: profile, run, commit, companions, out of scope | `findings.json` top-level fields |
| Scope: files reviewed, agents | ledger `reviewed_paths` and `agent_ids` of covered or candidate units, plus `detected_by` |
| Scope: stack, versions, advisories | `stack.json` |
| Posture | `findings.json` `posture` (written by the orchestrator), then computed totals |
| Findings, details, leads, needs validation | `records`, by verdict |
| Constraint / code quote | the lines `location.line`–`end_line` of `<repo>/<file>`, verbatim, at most 30 |
| Hardening notes | `findings.json` `hardening` |
| Coverage | ledger statuses only; load mode from `inventory.json` |

The assembler rejects the claims listed under Language in any free-text field.

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
| Files reviewed | `tally/circuit.go` · `tally/hints.go` · `contracts/Ballot.sol` |
| Stack | gnark v0.14.0 (advisories: 3) · groth16 · bn254 · solidity: yes · foundry: yes |
| Versions | `go.mod`: gnark v0.14.0, gnark-crypto v0.19.0, go 1.24.0 |
| Advisories | GHSA-7fx8-hmgc-82jp (high, fixed v0.16.4) · … |
| Companions | ✔ fp-check · ✖ circom-auditor |
| Agents | C1, I1, V-hints, V-range, …, G2 |
| Out of scope | <what and why> |

## 2. Posture

<findings.json posture: three to six sentences on the main trust assumptions
(setup, VK provenance, who submits proofs), the strongest and weakest areas,
and the single most important action. No marketing.>

Totals: 1 confirmed (1 high) · 0 needs validation · 2 leads · 1 rejected. Ledger: 14 of 20 applicable units examined.

(With no confirmed finding, the assembler adds that this does not mean the code
is free of bugs and points to section 8.)

## 3. Findings

| # | Title | Severity | Confidence | Evidence | Detected by |
|---|---|---|---|---|---|
| 1 | Mean hint output is never bound | high | 90 | POC | C1, V-hints |

## 4. Finding details

### 1. <Title>

`TallyCircuit.Define` · `tally/circuit.go:40-44` · severity **high** · confidence 90 · evidence **POC** · detected by C1, V-hints · vectors V-H3

**Description.** <one sentence from the record>

Also at: `Ballot.cast` `contracts/Ballot.sol:31`     (related_locations, if any)

**Description.** <one sentence from the record>

**Constraint.** `tally/circuit.go:40-44`     ("Code." for non-circuit layers)

```go
<the offending lines, verbatim>
```

**Attack witness.** <the record's proof field>

**Impact.** <impact>

**PoC.** `pocs/<file>` — `go test -run PoC_1 ./circuit` → demonstrated.

**Fix.** <fix summary>

Option A — <label>

```diff
<verbatim diff>
```

**Chain.** `<fingerprint>` → …     (if chain)

**Refuter.** exploitable — <one paragraph> (by fp-check)

## 5. Leads

Trails worth manual work. No severity, no fix.

- **<title>** — `scope` · `file:line` · detected by … — <description>. Smells: <code_smells>. Unverified: <unverified>.

## 6. Needs validation

| Item | Severity | Confidence | Blockers | How to validate |
|---|---|---|---|---|

## 7. Hardening notes

Optional, short: hygiene that is not a vulnerability (stale verifier file in the
repo, no public-input-order test, `api.Println` in a circuit).

## 8. Coverage

| Kind | Units | planned | in progress | covered | candidate | deferred | blocked | not applicable | out of scope |
|---|---|---|---|---|---|---|---|---|---|

Examined (covered or candidate): X of Y applicable units (Z%).

- Units not examined, with status and reason (copied from the ledger).
- Units not applicable or out of scope, with reasons.
- Rejected candidates: N (kept in `findings.json`).
- Companions not available.
- Load mode of the inventory (`types` / `syntax` / `mixed`) and its errors.

> This review is a time-boxed, best-effort search for bugs by an automated
> agent. It is not a guarantee of security. Absence of a finding is not
> evidence of absence of bugs.
````

## Rules

- Findings (section 3) are the `confirmed` records, sorted by severity, then
  confidence (highest first), then title. Needs-validation rows use the same
  order. Leads are sorted by file and line.
- A confirmed finding below confidence 80 prints description, constraint,
  witness and impact, but no fix block unless one exists.
- Keep a finding the refuter marked `not_exploitable` only if a gate still
  passed. The assembler then prints the gates next to the refuter's view.
- KNOWN / NEW tags (`run_tag`, with `--loop`) go after the title: `[KNOWN]`.
  The orchestrator prints `seen in k/N passes` itself.
- The coverage section is mandatory, even with zero findings.
