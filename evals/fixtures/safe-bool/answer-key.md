# Answer key — safe-bool fixture (all-safe)

Fixture: `testdata/safe-bool` (gnark v0.14.0, Groth16, BN254). This is a **correct**
circuit: A policy that asserts its flags boolean before combining them (the correct counterpart of boolean-missing).

There are **no planted items**. Recall is undefined (reported as "–"). Any
`confirmed` or `needs_validation` record is a **false positive**; a `lead` or
`hardening` note on the correctly constrained shape is tolerated noise (decoy
D1). The rejection test under `pocs/` shows the attack that works on the unsound
counterpart is rejected here.
