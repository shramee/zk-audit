# Answer key — input-order fixture

Fixture: `testdata/input-order` (gnark v0.14.0 circuit + Solidity mixer, Foundry).
The circuit's public-witness order is `[root, nullifier, recipient, value]`.
Audits run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | The `input` array swaps the nullifier and recipient slots versus the circuit's public-witness order. | **High integration.** The array the verifier checks does not match what the circuit committed, so the on-chain binding of nullifier and recipient is wrong: at minimum every honest proof fails, and in general the contract keys `spent` and pays out on fields the proof never bound. Foundry PoC: `test_OrderMismatchBreaksVerification` (an honest withdrawal reverts under a faithful verifier). | confirmed, high/medium |

Contract input order differs from the public-witness order (V-PI1). The
public-witness order is the struct-walk order; the contract must match it
element for element.
