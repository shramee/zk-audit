# Changelog

All notable changes to the zk-audit plugin are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions
follow [Semantic Versioning](https://semver.org/). A release is the tag
`zk-audit--vX.Y.Z` (the name `claude plugin tag` creates); the release
workflow publishes the section of that version as the release notes.

The version (`plugins/zk-audit/skills/zk-audit/VERSION`, `plugin.json`, the
marketplace entry and the tool's `Version`) is still 0.1.0 and has not been
released. To release: move the Unreleased entries under a new version
heading, bump the four version fields together, run `make release-check`,
then `claude plugin tag plugins/zk-audit --push`.

## [Unreleased]

Everything since the plugin scaffold, the `gnark-inventory` recon tool, the
knowledge base, the report assembler and the self-contained skill folder
(shramee/zk-audit#4 to #7): the follow-up list, items 4 to 30, in
shramee/zk-audit#8 to #16.

### Added

- **Eval harness** (shramee/zk-audit#9): cases in the `claude plugin eval`
  format (pool at quick, standard and deep, trigger and negative-trigger
  cases), a deterministic scorer (`evals/score`: recall, critical recall,
  false positives, precision, severity agreement, PoC rate, cost, time) that
  locates key items by code anchors, `evals/run-audit` for headless audit
  runs under a budget cap, and `make eval-audit`.
- **Measured baseline** (shramee/zk-audit#10): one blind run per profile on
  the pool fixture (2026-10-29, `e198ed7`): quick 12/14, standard 12/14, deep
  13/14 (12 found, 2 partial), 0 false positives after the key fixes; 9.16,
  26.09 and 25.64 USD; a friction list and a prioritized fix list.
- **Safety by code** (shramee/zk-audit#11): `profiles.json` as the one source
  of lenses and profiles (`gnark-inventory profiles`, generated doc tables);
  `args` parses the invocation; read-only `zk-audit:hunter` and
  `zk-audit:critic` agent types; `gnark-inventory sandbox` (bubblewrap on
  Linux, `sandbox-exec` on macOS) for PoCs and type loading; writes into the
  target refused; `validate --out` and `assemble` check PoC files and saved
  agent outputs; `diff` triggers from git objects only; tool-held loop memory
  (`memory init|merge|known|status`); `ledger mark|add|show` and
  `agents save|list`.
- **Lenses** (shramee/zk-audit#13): T1 trusted parties (quick, standard,
  deep) with privileged functions, roles and upgrade paths in the Solidity
  inventory; PR1 privacy (standard, deep) and V-PR vectors; gas and liveness
  vectors (V-LV) and the `liveness` ledger class; severity calibration (21
  `SC-*` anchors backed by 60 published findings, checked by `validate`);
  report sections Trusted parties, Privacy and Not covered.
- **Solidity side** (shramee/zk-audit#14): S1 contract review and
  V-contract, V-custom for hand-written and non-gnark verifiers,
  `gnark-inventory convert pashov` for `solidity-auditor` output, verifier
  provenance (`verifier abi|diff|vk|bytecode|regen|ceremony`, the ABI check
  against the exported verifier in every profile, `regen` in deep), Solidity
  inheritance, imports, libraries and low-level calls, and a Foundry PoC
  against a real gnark-exported verifier in CI.
- **Library mode** (shramee/zk-audit#15): gadget-library detection, the
  exported-gadget inventory, lens L1 (doc contract vs enforced
  constraints), the per-gadget PoC harness, differential-test templates;
  `preflight` for the module cache and Go toolchain; the gnark version
  support matrix (`test/versions/run`, CI on v0.10.0, v0.14.0, v0.16.4);
  the gnark-crypto advisory rows and an opt-in OSV freshness check.
- **Product and operations** (shramee/zk-audit#16):
  - `gnark-inventory estimate`: agents, tokens, cost and minutes per profile
    as ranges before the first spawn, calibrated on the measured runs and
    shown in the profile question.
  - `--budget USD`, the spend ledger (`agents save --tokens`, `budget
    record|check|show`) and a stop before any wave that would cross the
    budget, with a partial report.
  - `/zk-audit resume [run-id|out-dir]` (`args --save` writes `run.json`;
    `gnark-inventory status` names the first incomplete step and never
    respawns a saved agent); the agent recovery rule for every agent kind.
  - `gnark-inventory critic-check`: missing units computed from the ledger,
    the inventory and the saved outputs, a decision required for each
    (`--verify`); the model critic reports only lens-level gaps.
  - The threat-model file: `templates/zk-audit.md`, `gnark-inventory
    threat-model` and `schemas/threat-model.schema.json`; bundles inline it,
    `validate` checks accepted risks against it, the report renders its
    scope, deployment facts, unrecorded accepted risks and prior findings.
  - Report: spend, a partial-report notice, and not-covered lines for
    library mode, lenses skipped by a condition or an empty shard, a budget
    stop, agents that did not finish and `--no-poc`.
  - CI: `claude plugin validate`, a gofmt check over every module, test
    coverage with a floor, the release check and a release workflow;
    `docs/licence-options.md`; the pilot protocol (`docs/pilots.md`,
    `evals/pilots/`).

### Changed

- `evals/` and `testdata/` moved out of the plugin, so neither install ships
  answer keys or planted-bug comments (shramee/zk-audit#8).
- PoC and recon commands are single commands (`go -C`, `forge --root`)
  that permission allowlists accept (shramee/zk-audit#11).
- Admin powers are `needs_validation` with a `trust` blocker instead of "do
  not report" (shramee/zk-audit#13).
- The profile question is asked after the inventory, with the estimate; the
  coverage critic no longer lists what `critic-check` computes
  (shramee/zk-audit#16).

### Fixed

- `gnark-api-footguns.md` said `eddsa.Verify` asserts `A` and `R` on the
  curve; at the pinned versions it does neither (shramee/zk-audit#13).
- The scorer read an item from a record that only named its file as a
  related location; decoy D5 matched correct on-curve findings
  (shramee/zk-audit#10).
- Loop mode counted a targeted wave as a pass and never applied the stop
  rule; it is now held by the tool (shramee/zk-audit#11).
- `candidate` ledger units no longer count as examined
  (shramee/zk-audit#11).
