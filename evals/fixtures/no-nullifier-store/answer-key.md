# Answer key — no-nullifier-store fixture

Fixture: `testdata/no-nullifier-store` (gnark v0.14.0 circuit + a Solidity mixer,
Foundry). Audits run on the sanitized copy; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| I1 | `contracts/Mixer.sol` `withdraw` | The `spent` mapping is declared but never written, and `withdraw` never checks it. | **Critical integration.** The same proof and nullifier withdraw repeatedly; a single valid note drains the pool. Foundry PoC: `test_DoubleSpend` (two withdrawals with nullifier 7 both pay out). | confirmed, critical/high |

The circuit itself is a correct `Nullifier = MiMC(Secret)` binding; the bug is
the missing on-chain nullifier store. Reports that blame the circuit are wrong.
