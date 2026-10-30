# Answer key — missing-root-check fixture

Fixture: `testdata/missing-root-check` (gnark v0.14.0 circuit + Solidity mixer, Foundry). Audits
run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | `knownRoots` exists and `addRoot` fills it, but `withdraw` never checks `knownRoots[root]`. | **Critical integration.** A proof against an attacker-built tree (any root) is accepted, so the attacker mints funds from a fake tree. Foundry PoC: `test_ForgedRoot`. | confirmed, critical/high |

Deployed verifier accepts an unanchored root (V-VC / V-M4). The owner-only
addRoot is a separate trusted-party observation (O1).
