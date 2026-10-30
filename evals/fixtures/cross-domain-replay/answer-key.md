# Answer key — cross-domain-replay fixture

Fixture: `testdata/cross-domain-replay` (gnark v0.14.0 circuit + Solidity mixer, Foundry). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | The proof statement is `[root, nullifier, recipient, value]` with no chain id or contract address. | **High integration.** A proof made for one deployment is accepted by any other deployment sharing the verifier and the root, so one note is spent on several contracts. Foundry PoC: `test_CrossDeploymentReplay` (same proof withdraws from two mixers). | confirmed, high/medium |

Proof not bound to chain, contract or epoch (V-PI5). The owner-only addRoot is a
separate trusted-party observation (O1). Not the same as the stale-root window
(`testdata/liveness-roots`, owned by another agent).
