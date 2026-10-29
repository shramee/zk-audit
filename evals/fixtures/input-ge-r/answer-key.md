# Answer key — input-ge-r fixture

Fixture: `testdata/input-ge-r` (gnark v0.14.0 circuit + Solidity mixer, Foundry). Audits
run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | The `nullifier` keys the `spent` map without first requiring `nullifier < R`. | **High integration.** A pairing verifier reduces public inputs modulo R, so `nullifier` and `nullifier + R` verify the same note but are distinct keys in `spent`, giving an aliasing double-spend. Foundry PoC: `test_AliasDoubleSpend`. | confirmed, high/critical |

Public inputs >= r alias in custom verifiers or callers (V-PI3).
