# Answer key — omit-modulus fixture

Fixture: `testdata/omit-modulus` (gnark v0.14.0, Groth16, BN254). Audits run on the
sanitized copy from `evals/sanitize omit-modulus <scratch>`; match by code, not line.

## Planted items

| Id | Location | Defect | Real impact | Expected |
|---|---|---|---|---|
| R1 | `circuit/circuit.go` Define | 254 prover-supplied bits are recomposed over the field and checked against `Value`, with no check that they are the canonical (< r) decomposition; the top bit is exposed as `Positive`. | **High soundness.** The bits of `Value` and of `Value+r` both recompose to `Value` and differ in the high bits (r has bit 253 set), so `Positive` is prover-chosen and not a function of `Value`. This is the `bits.OmitModulusCheck` footgun. PoC: `TestPoC_NonCanonicalDecomposition`. | confirmed, high/medium |

Full-width decomposition accepts `a` and `a + r` (V-R1).
