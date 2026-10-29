# Evals

Everything here stays out of the plugin install: a plugin install copies
`plugins/zk-audit/` and a standalone install copies the skill folder, and
neither contains `evals/` or `testdata/` (`TestInstallShipsNoFixtures`).

## Layout

```text
evals/
  cases/<case>/          one eval case in the `claude plugin eval` format
    case.yaml            name, tags, runs (3), scaffold, graders
    prompt.md            front matter (max_turns, timeout, allowed_tools) + prompt
    scaffold.sh          names the fixture: exec ../../lib/scaffold-audit <fixture>
  fixtures/<fixture>/    eval metadata for testdata/<fixture>
    key.json             machine-readable answer key (evals/score reads it)
    answer-key.md        the reviewed ground truth, for people
    sanitize.sed         strips planted-bug comments before a blind run
    pocs/                hand-written PoCs that pin the PoC templates
  lib/scaffold-audit     prepares a run workspace (see below)
  score/                 deterministic scorer (Go, no dependencies)
  run-audit              headless runner for audit cases: N runs, then score
  sanitize, run-pocs     fixture copy without hints; run the fixture PoCs
  baseline/              recorded runs
```

## Case kinds

| Kind | Tags | Runner | Scored by |
|---|---|---|---|
| Audit of a fixture | `audit` | `evals/run-audit` (or `claude plugin eval` on a non-root host) | `evals/score` against `key.json`; LLM graders in `case.yaml` |
| Trigger and negative trigger | `trigger` | `claude plugin eval` | `tool_used` and LLM graders |

## Running

Trigger cases (no shell writes, run anywhere):

```bash
claude plugin eval . --tag trigger --trust-plugin --scaffold --no-publish --max-cost-usd 5
```

Run it on the repository root, not on `plugins/zk-audit`: the CLI reads cases
below the directory it is given, and each case loads the plugin with
`plugins: ["../../../plugins/zk-audit"]`. The CLI runs every case with and
without the plugin and reports the difference.

Audit cases, three runs each, scored:

```bash
evals/run-audit --runs 3 --budget 30 pool-quick
make eval-audit CASES="pool-quick pool-standard" RUNS=3 BUDGET=60
```

`run-audit` exists because the `claude plugin eval` sandbox gives a root
user no writable directory for shell commands, and an audit needs one (Go
build cache, output directory, PoC worktree). It uses the same case files.
Per run it:

1. runs the case's `scaffold.sh` in a fresh workspace with a throwaway HOME:
   a sanitized copy of the fixture in `./target`, a Go env file that points
   at the shared module cache (`.cache/gomod`, filled from GOPROXY on first
   use) and keeps the go command offline, and a prebuilt `gnark-inventory`;
2. runs `claude -p` on the prompt with a tool allowlist, deny rules on
   `evals/`, `testdata/`, `docs/` and `PLAN.md`, and `--max-budget-usd`;
3. scores `./out/findings.json` with `evals/score` and records cost and time.

It writes `evals/results/<time>/<case>/run<i>/` and `summary.md` (mean,
spread, per-item outcomes).

## Scoring

`evals/score run --key key.json --target <sanitized tree> --findings findings.json`
matches every record and hardening note to the key:

- An item is located by code **anchors**, not line numbers, so the key works
  on the sanitized copy. A missing anchor is an error (key and fixture
  drifted).
- A record matches an item when one of its locations is within 3 lines of
  the item's range and its text matches the item's `match` regex
  (`match_in: "title"` restricts the regex to title, bug class and
  fingerprint).
- **found**: a matching record in an `expect` class; **partial**: only in a
  `partial` class; else **missed**. Recall = (found + 0.5·partial) / items.
- **False positive**: a `confirmed` or `needs_validation` record that matches
  a decoy, or matches no item and no `other` observation. Unmatched leads and
  hardening notes are **noise**.
- Also reported: critical recall, precision over claims, severity agreement,
  PoC rate (confirmed circuit records with a demonstrated PoC), cost, time.

`evals/score summarize <score.json>...` aggregates runs per case.
