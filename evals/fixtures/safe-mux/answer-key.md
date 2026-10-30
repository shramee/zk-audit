# Answer key — safe-mux fixture (all-safe)

Fixture: `testdata/safe-mux` (gnark v0.14.0, Groth16, BN254). This is a **correct**
circuit: A mux built with api.Select, which asserts the selector boolean (the correct counterpart of nonbool-mux).

There are **no planted items**. Recall is undefined (reported as "–"). Any
`confirmed` or `needs_validation` record is a **false positive**; a `lead` or
`hardening` note on the correctly constrained shape is tolerated noise (decoy
D1). The rejection test under `pocs/` shows the attack that works on the unsound
counterpart is rejected here.
