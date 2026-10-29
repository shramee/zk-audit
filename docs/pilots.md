# Pilot audits beside a human auditor

The fixtures in `evals/` measure recall on bugs someone planted. A pilot
measures the skill on a real gnark codebase against a human auditor's
review of the same commit.

**Pass criterion (the owner's words):** two pilot audits beside a human
auditor, passing when the human finds no high or critical miss twice in a
row. In this protocol: two consecutive pilots in which zk-audit misses none
of the human's high or critical findings (the definition of a miss is
below).

**Status: no pilot has been run.** Running one needs a human auditor engaged
on a real codebase; this repository holds the protocol and the tooling
(`evals/pilots/`, `evals/score pilot`), not results. Results go in
[`evals/pilots/results.md`](../evals/pilots/results.md).

## 1. Choosing a target

A pilot target is:

- **a real gnark codebase** under review by a human auditor, independently
  of zk-audit: a paid engagement, an internal security review, or a contest
  with a published report. Production circuits with a verifier integration
  are the main case; a gadget library counts as a library-mode pilot,
  recorded on its own line;
- **reviewed at one fixed commit** by both sides. The human's scope (files,
  contracts) is the pilot's scope; pass it to zk-audit as scope paths or as
  the `zk-audit.md` scope;
- **never used to develop the skill** before the pilot: no fixture, vector
  or lens was written from it (PLAN §10 Q4 asks for held-out targets);
- **cleared with the code owner** for an AI-assisted review: the code goes
  to the model provider under the account's data terms. Without written
  consent, it is not a pilot target;
- **within budget**: run `gnark-inventory estimate` on it first (the
  estimate needs only the inventory) and agree the budget with whoever
  pays.

Prefer targets that differ from the previous pilot (another protocol shape,
another gnark version) so two passes do not test the same thing twice.

## 2. Blinding

- zk-audit runs on the pilot commit **before** the operator sees the human's
  findings, notes or draft report, and the operator does not steer it
  (default answers to the profile question, no hints in the prompt, no
  edits to `findings.json`). A `zk-audit.md` written by the code owner is
  allowed; one written by the human auditor or from their notes is not.
- The human auditor does not see zk-audit's output until their own report
  is final, so the key does not depend on the run.
- The plugin revision is frozen for the pilot: record its commit. Changing
  the skill between the run and the scoring voids the pilot.

## 3. Running zk-audit

Run both profiles, standard and deep, once each, each in its own session
and output directory:

```text
/zk-audit standard --out <pilot dir>/standard --budget <agreed USD>
/zk-audit deep --out <pilot dir>/deep --budget <agreed USD>
```

Record per run: plugin revision, model, `spend.json` totals and the
session's `total_cost_usd` when the runtime shows it, wall-clock time, and
whether a budget stop or a blocked agent happened (the report says so).
Keep the output directories, `REPORT.md` and `pocs/` with the pilot's
private material; they are evidence for the hand check.

## 4. Building the key from the human's report

When the human's report is final, the human (or the operator with the
human checking) writes their findings in
`evals/pilots/human-findings.template.json` or `.md`:

- one entry per finding in the pilot scope, with the id from the report;
- severity on zk-audit's scale. Map the auditor's scale first: Critical →
  critical; High → high; Medium → medium; Low → low; Informational, Gas,
  Best practice → info. A scale with no critical (zkSecurity's) maps its
  High to `high`, and to `critical` only when the finding lets anyone forge
  proofs or move funds without a precondition;
- the place: `file:line` or `file:line-end` at the pilot commit, plus
  further places in `also`;
- optionally a `match` regular expression, when several bugs share the
  same lines, so that a zk-audit record about another bug there does not
  count.

The scorer turns this into an answer key with line ranges (the tree is not
sanitized, so lines are stable): `evals/score pilot --key-out key.json`.

## 5. Scoring

```bash
evals/pilots/score-pilot <human findings> <tree at the pilot commit> <out>/findings.json [<result dir>]
```

It writes `key.json` and `pilot.json` and prints the row for
`results.md`. A zk-audit record matches a human finding when one of its
locations is within three lines of the finding's range and, when the
finding has a `match`, its title, description, bug class or fingerprint
matches it. For each human finding the outcome is:

| zk-audit's best matching record | Outcome |
|---|---|
| `confirmed` or `needs_validation` | found |
| `lead` | lead only |
| none, `rejected`, or only a hardening note | missed |

Then **check every outcome by hand**, as for the measured runs
(`evals/baseline/`): read the matching record and decide whether it
describes the same bug. Correct the automatic outcome where it is wrong and
say why in the notes. Also classify every unmatched zk-audit claim
(`unmatched_claims`: confirmed or needs-validation records at no human
finding) as a true bug the human missed, a false positive, or a duplicate;
send true bugs to the code owner like any other finding.

## 6. What counts as a miss

A high or critical finding of the human is **missed** when, after the hand
check, the report of the profile under test does not name the bug as a
confirmed finding, a needs-validation item or a lead:

- no record at the place, or records there about other bugs;
- the right place, but the record is `rejected` (zk-audit looked and
  dismissed it);
- only a hardening note, or only posture text;
- the bug is in a file zk-audit's ledger shows as not examined (deferred,
  blocked, out of scope) or that a budget stop cut: coverage gaps are misses.

Not a miss:

- a `lead` that names the mechanism. It is counted separately ("lead
  only") because it means zk-audit did not confirm what the human did; a
  pilot with lead-only high or critical findings passes but the row says
  so;
- a finding outside the pilot scope, or one that needs facts no reviewer
  of the repository could have (the deployed key, an off-repository
  service), which zk-audit lists under needs validation or not covered.

Severity disagreement on a found item (zk-audit says medium, the human
says high) is recorded in the score's `severity_agreement`, not a miss.

## 7. The pass criterion

- A pilot **passes for a profile** when that profile's run has no high or
  critical miss after the hand check.
- The criterion is met when **the same profile** passes two pilots in a
  row, on two different targets, with no failing pilot of that profile in
  between. A failing pilot resets the count to zero.
- Standard is the profile under test (the default); deep is run and
  recorded beside it. The criterion is met for whichever profile reaches two
  consecutive passes first; the README says which.
- Changing the skill after a failing pilot is expected; the next pilot then
  needs a new target, and the row records the new plugin revision.

## 8. Recording results

- Add one row per pilot and profile to `evals/pilots/results.md` (the
  script's row plus profile, revision, model, cost, time, unmatched-claim
  classification and date) and update its status line and the README's
  pilot line.
- Real codebases are often private. The repository records only counts,
  ids and the pass or fail, unless the code owner agrees to more. Keep the
  human's findings file, `key.json`, `pilot.json`, the zk-audit output and
  the hand-check notes with the engagement's private material.
- For every miss, write a one-line cause (no lens for it, a lens that read
  the file and missed it, a coverage gap, a rejected record, judging
  demoted it) and open an issue: misses are the input to the next skill
  change.
