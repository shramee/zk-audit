# Answer key — point-oncurve fixture

Fixture: `testdata/point-oncurve` (gnark v0.14.0, Groth16, BN254). Audits run on the sanitized copy; match by code.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| E1 | `circuit/circuit.go` Define | The public key `(X, Y)` is hashed into the identity but never asserted on the curve (`curve.AssertIsOnCurve`). | **High soundness.** An off-curve or low-order point is registered as a valid key, enabling small-subgroup / invalid-key attacks in the surrounding signature or key-agreement protocol. PoC: `TestPoC_OffCurveKeyRegistered` (the off-curve point `(3,5)` registers, while the omitted on-curve check rejects it). | confirmed, high/medium |

Points used without curve or subgroup checks (V-E4).
