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
    pocs/                hand-written PoCs: *_test.go (Go) and/or *.t.sol (Foundry)
  lib/scaffold-audit     prepares a run workspace from testdata/<fixture>
  lib/scaffold-real      fetches a real repo at a pinned commit (proxy, cached)
  score/                 deterministic scorer (Go, no dependencies)
  run-audit              headless runner for audit cases: N runs, then score
  sanitize               fixture copy without hints
  run-pocs               run a fixture's (or all fixtures') Go and Foundry PoCs in the sandbox
  baseline/              recorded runs
```

## Case kinds

| Kind | Tags | Runner | Scored by |
|---|---|---|---|
| Audit of a fixture | `audit` | `evals/run-audit` (or `claude plugin eval` on a non-root host) | `evals/score` against `key.json`; LLM graders in `case.yaml` |
| Trigger and negative trigger | `trigger` | `claude plugin eval` | `tool_used` and LLM graders |

Audit cases also carry one of `planted` (a seeded bug), `safe` (no bug),
`advisory` (a vulnerable gnark version), `real` (a real repo fetched at a pinned
commit), plus a class tag (`soundness`, `integration`, `dependency`, …).

## Corpus

Fixtures live in `testdata/<name>/` (planted, safe and advisory) or are fetched
at a pinned commit by `evals/lib/scaffold-real` (real). Each has
`evals/fixtures/<name>/{key.json, answer-key.md, sanitize.sed, pocs/}`. "PoC"
is how the planted bug was shown to be real: a Go test run by `evals/run-pocs`
(T-* templates), a `forge` test run by `evals/run-pocs` against a mock
verifier, a public audit **report**, or Phase-0 **version** detection.

### Planted — circuit (soundness)

| Fixture | Bug (vector) | Foundry | PoC |
|---|---|---|---|
| hint-raw | hint output published with no binding constraint (V-H1) | – | Go |
| hint-remainder | Euclidean remainder not range-bounded, quotient free (V-H3) | – | Go |
| hint-helper | helper returns unconstrained hint outputs (V-H7) | – | Go |
| revenue-wrap | native multiplication of 128-bit factors wraps the field (V-F6) | – | Go |
| zero-test | inverse-based zero test missing `Value*flag == 0` (V-F2/H1) | – | Go |
| nonbool-mux | hand-rolled mux selector not asserted boolean (V-S2) | – | Go |
| cmp-bound | bounded comparator on un-range-checked operands (V-R4) | – | Go |
| omit-modulus | full-width recomposition without a canonical `< r` check (V-R1) | – | Go |
| merkle-sentinel | empty-slot sentinel leaf accepted as a member (V-PS3) | – | Go |
| unused-public | public input no constraint uses (V-PI2) | – | Go |
| boolean-missing | boolean algebra without `AssertIsBoolean` (V-G2) | – | Go |
| go-branch-skip | quorum check gated by a compile-time Go branch (V-S1) | – | Go |
| limb-unchecked | high limb not range-checked, amount unbounded (V-H2) | – | Go |
| onehot-nonunique | one-hot selector sum not pinned to 1 (V-G3) | – | Go |
| point-oncurve | public key used without an on-curve check (V-E4) | – | Go |
| range-partition | low/high split ranges overlap, high part free (V-R6) | – | Go |
| vk-recursion | inner verifying key is a free witness (V-CM4) | – | review¹ |
| ci-smoke | square-root hint output unconstrained (the CI case) | – | Go |
| pool | multi-bug shielded-pool fixture (see its answer key) | yes | Go |

¹ `vk-recursion` is a valid in-circuit Groth16 verifier; compiling the recursive
R1CS and forging a second VK is too heavy for the harness, so the under-constraint
is located structurally and confirmed by review rather than an executed PoC.

### Planted — integration (Foundry)

| Fixture | Bug (vector) | Foundry | PoC |
|---|---|---|---|
| no-nullifier-store | nullifier never recorded, proofs replay (double spend) | yes | forge |
| proof-malleable | replay protection keyed on `keccak256(proof)` (V-PS1) | yes | forge |
| no-recipient-bind | recipient not in the proof statement, front-running (V-PI4) | yes | forge |
| input-ge-r | nullifier keyed without a `< r` check, aliasing (V-PI3) | yes | forge |
| missing-root-check | withdraw never checks `knownRoots[root]` (V-VC/M4) | yes | forge |
| input-order | verifier input array order ≠ public-witness order (V-PI1) | yes | forge |
| cross-domain-replay | no chain/contract binding, proof replays across deployments (V-PI5) | yes | forge |

### Planted — liveness, ABI and library (not circuit soundness)

| Fixture | Bug | Foundry | PoC |
|---|---|---|---|
| liveness-roots | root ring buffer evicts a pending withdrawal's root (liveness; Foundry, no gnark) | yes | forge |
| sol-gnark-abi | caller's verifier interface does not match the gnark-exported verifier (completeness) | yes | forge, real proof |
| lib-gadgets | library mode: four gadgets break their documented contracts | – | Go (harness wrappers) |

### Advisory replays (dependency)

| Fixture | gnark | Advisory | PoC |
|---|---|---|---|
| adv-eddsa | v0.13.0 | CVE-2025-57801 EdDSA/ECDSA malleability | version |
| adv-commit | v0.10.0 | CVE-2024-45039 / 45040 commitments | version |
| adv-cmp | v0.8.1 | CVE-2023-44378 Cmp/ToBinary | version |
| adv-emulated | v0.16.1 | GHSA-3mvx emulated arithmetic (needs Go ≥ 1.25.7) | version |

### Real repositories

| Case | Repo @ commit | Ground truth | PoC |
|---|---|---|---|
| real-plonky2 | succinctlabs/gnark-plonky2-verifier @ 89b5a01 | Veridise `VAR_Succinct-V1` (3 critical Goldilocks under-constraints) | report |
| real-semaphore | worldcoin/semaphore-mtb (gnark v0.8.0) | dependency-only (no report in snapshot; circuit findings unscored) | report (limited) |

### All-safe (no planted bug; any confirmed record is a false positive)

| Fixture | Correct counterpart of | Foundry | PoC (shows the attack rejected) |
|---|---|---|---|
| safe-hint | hint-remainder | – | Go |
| safe-zero | zero-test | – | Go |
| safe-mux | nonbool-mux | – | Go |
| safe-merkle | merkle-sentinel | – | Go |
| safe-revenue | revenue-wrap | – | Go |
| safe-range | cmp-bound | – | Go |
| safe-canonical | omit-modulus | – | Go |
| safe-bool | boolean-missing | – | Go |
| safe-epoch | unused-public | – | Go |
| safe-mixer | the integration fixtures | yes | forge |

## Running

Trigger cases (no shell writes, run anywhere):

```bash
claude plugin eval . --tag trigger --trust-plugin --scaffold --no-publish --max-cost-usd 5
```

Run it on the repository root, not on `plugins/zk-audit`: the CLI reads cases
below the directory it is given, and each case loads the plugin with
`plugins: ["../../../plugins/zk-audit"]`. The CLI runs every case with and
without the plugin and reports the difference.

Fixture PoCs (offline after `make fixtures`; no model calls):

```bash
make eval-pocs           # every fixture's Go and forge PoCs, sanitized copies, in the sandbox (needs forge)
evals/run-pocs <fixture> "$(mktemp -d)"   # one fixture (`all` runs every one)
```

Audit cases, three runs each, scored (these cost money):

```bash
evals/run-audit --runs 3 --budget 30 pool-quick
evals/run-audit --runs 1 --budget 4 ci-smoke          # the cheap CI case
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

**Check every outcome by hand.** The scorer is regex and location matching; the key
is a human's reading of the fixture. Read each record behind each outcome before
trusting a figure. The 2026-10-29 runs found a decoy whose pattern was too wide and
two true observations the key did not list; the fixes are in `key.json` and
`answer-key.md`, with a scorer test for the tie-break. A rejected record does not
count as a found item (the key asks for a lead, info or hardening note).

## Recorded runs

`baseline/` holds one markdown file per measurement session and the
`findings.json` of each run. Scores below use the key as of the 2026-10-29
measurement; the first run was re-scored with it.

| Date | Case, profile | Revision | Recall | False positives | Cost (USD) | Time (min) | Record |
|---|---|---|---|---|---|---|---|
| 2026-10-27 | pool, quick `--no-poc` | `f5a730f` | 12 / 14 (86 %) | 0 | about 10.7 | 9.3 | [`pool-quick.md`](baseline/pool-quick.md) (history) |
| 2026-10-29 | pool, quick `--no-poc` | `e198ed7` | 12 / 14 (86 %) | 0 | 9.16 | 10.7 | [`pool-2026-10-29.md`](baseline/pool-2026-10-29.md) (current) |
| 2026-10-29 | pool, standard | `e198ed7` | 12 / 14 (86 %) | 0 | 26.09 | 22.8 | same file |
| 2026-10-29 | pool, deep | `e198ed7` | 13 / 14 (93 %; 12 found, 2 partial) | 0 | 25.64 | 21.8 | same file |

One run per row; no variance estimate. Deep ran one of its three passes (see the
baseline file).
