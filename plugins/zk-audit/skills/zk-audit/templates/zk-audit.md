# zk-audit threat model

<!--
Copy this file to zk-audit.md at the root of the repository and fill it in.
`gnark-inventory threat-model --repo <repo>` parses it into threat-model.json,
which every agent bundle, the judge and the report use. Keep the "## "
headings and the table header rows: the parser reads them. Replace every
<placeholder> row with real rows, or delete it; a row that still holds a
placeholder is ignored. Ids look like PROP-1, AR-1, PF-1.

This file states intent. It never excuses a missing constraint: a power you
accept here is still reported, as an accepted risk, with this file's line.
-->

## Scope

In-scope paths, relative to the repository root. Without any, the whole
repository is in scope.

- <circuits/>
- <contracts/Ballot.sol>

## Out of scope

| Path or area | Reason |
|---|---|
| <contracts/mocks/> | <test helpers, never deployed> |

## Trusted parties

Trust levels: `trusted` (its powers are accepted risks), `bounded` (trusted
only within the limit in Notes; a power beyond it is a finding), `untrusted`
(treated as an attacker).

| Party | Trust | Powers | Notes |
|---|---|---|---|
| <owner> | <trusted> | <replaces the verifier, posts Merkle roots> | <3-of-5 multisig behind a 48 h timelock> |
| <relayer> | <untrusted> | <submits proofs, chooses the fee> | <anyone can run one> |

## Properties

What must hold whatever any untrusted party does.

| Id | Property |
|---|---|
| <PROP-1> | <A ballot is counted at most once per voter and election.> |

## Accepted risks

Risks the project accepts. The party must be `trusted` or `bounded` above.

| Id | Party | Risk | Notes |
|---|---|---|---|
| <AR-1> | <owner> | <can replace the verifier without delay> | <governance decision; see GOVERNANCE.md> |

## Prior findings

Findings of earlier reviews, so this run reports them as known and flags a
fixed one that comes back. The fingerprint is the record's `group_key`
(`<circuit or contract>|<function or signal>|<bug-class>`). Status: open,
fixed, acknowledged, wont-fix, duplicate.

| Id | Fingerprint | Status | Title |
|---|---|---|---|
| <PF-1> | <BallotCircuit\|tally\|hint-unbound> | <fixed> | <Tally hint output is not constrained> |

## Deployment

Facts the code cannot show. Unknown facts stay out; the report then names
them as questions.

| Fact | Value |
|---|---|
| <verifier> | <contracts/Verifier.sol, deployed at 0x... on chain 1> |
| <verifying key> | <keys/ballot.vk, sha256 ...> |
| <ceremony> | <phase 1: a public powers-of-tau; phase 2: 4 independent contributors, transcript at ...> |
| <chain ids> | <1, 10> |
| <prover> | <users prove in the browser; no prover service> |
