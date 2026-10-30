# Answer key — safe-epoch fixture (all-safe)

Fixture: `testdata/safe-epoch` (gnark v0.14.0, Groth16, BN254). This is a **correct**
circuit: A ticket that absorbs the epoch into its commitment (the correct counterpart of unused-public).

There are **no planted items**. Recall is undefined (reported as "–"). Any
`confirmed` or `needs_validation` record is a **false positive**; a `lead` or
`hardening` note on the correctly constrained shape is tolerated noise (decoy
D1). The rejection test under `pocs/` shows the attack that works on the unsound
counterpart is rejected here.
