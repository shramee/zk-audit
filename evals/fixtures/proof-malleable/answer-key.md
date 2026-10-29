# Answer key — proof-malleable fixture

Fixture: `testdata/proof-malleable` (gnark v0.14.0 circuit + Solidity mixer, Foundry). Audits
run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | Replay protection keys on `keccak256(proof)` instead of the nullifier. | **Critical integration.** Groth16 proof bytes are not unique; a re-randomized proof for the same nullifier has a different `keccak256`, so it passes `spent` again and double-spends. Foundry PoC: `test_MalleableReplay`. | confirmed, critical/high |

Replay protection keyed on proof bytes (V-PS1). Never key state on proof bytes.
