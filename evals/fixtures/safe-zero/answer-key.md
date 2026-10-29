# Answer key — safe-zero fixture (all-safe)

Fixture: `testdata/safe-zero` (gnark v0.14.0, Groth16, BN254). This is a **correct**
circuit: An inverse-based zero test with the Value*flag == 0 binding (the correct counterpart of zero-test).

There are **no planted items**. Recall is undefined (reported as "–"). Any
`confirmed` or `needs_validation` record is a **false positive**; a `lead` or
`hardening` note on the correctly constrained shape is tolerated noise (decoy
D1). The rejection test under `pocs/` shows the attack that works on the unsound
counterpart is rejected here.
