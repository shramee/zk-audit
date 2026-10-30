# Answer key — no-recipient-bind fixture

Fixture: `testdata/no-recipient-bind` (gnark v0.14.0 circuit + Solidity mixer, Foundry). Audits
run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | The proof statement is `[root, nullifier, value]`; `recipient` is not bound. | **High integration.** A front-runner observes a pending withdrawal and resubmits the same proof with their own `recipient`, capturing the payout. Foundry PoC: `test_FrontRunRecipient`. | confirmed, high/medium |

Proof not bound to the caller or recipient (V-PI4).
