# Answer key — safe-merkle fixture (all-safe)

Fixture: `testdata/safe-merkle` (gnark v0.14.0, Groth16, BN254). This is a **correct**
circuit: A Merkle membership check that rejects the empty sentinel leaf (the correct counterpart of merkle-sentinel).

There are **no planted items**. Recall is undefined (reported as "–"). Any
`confirmed` or `needs_validation` record is a **false positive**; a `lead` or
`hardening` note on the correctly constrained shape is tolerated noise (decoy
D1). The rejection test under `pocs/` shows the attack that works on the unsound
counterpart is rejected here.
