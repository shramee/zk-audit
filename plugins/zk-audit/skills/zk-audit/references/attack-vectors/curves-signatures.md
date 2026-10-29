# Attack vectors: curves and signatures

Slice: `std/signature/eddsa`, `std/signature/ecdsa`, `std/algebra` (native
and emulated curves, pairings), scalar multiplication, and identities derived
from keys. 7 vectors, V-E1–V-E7.

Mantra: **a signature gadget enforces only what its doc comment says it
asserts.** Canonical scalars, curve membership, subgroup membership and message
hashing are the caller's job unless stated otherwise.

---

**V-E1. Signature scalar not canonical: `S` and `S + n` both verify**

- **D:** Before gnark v0.14.0, `eddsa.Verify` and `ecdsa` verification used `S`
  without asserting `0 ≤ S < order`. `(R, S)` and `(R, S + n)` were both
  accepted. A protocol that derives a nullifier, replay key or "used signature"
  flag from the signature can be double-spent with the malleated copy.
- **FP:** gnark ≥ v0.14.0, where the gadget asserts `S < order`
  (`gnark/std/signature/eddsa/eddsa.go`), and no protocol identifier is derived
  from signature bytes.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj (CVE-2025-57801)
- **Seed:** FG-SIGNATURE; inventory: stack advisories
- **PoC:** T-INVALID-ASSIGNMENT

**V-E2. EdDSA public key accepted with a torsion component**

- **D:** `eddsa.Verify` checks neither that `A` is on the curve nor that it
  is of prime order: it only asserts the bound on `S`, that
  `[S]G - [h]A` is on the curve, and that `[cofactor]([S]G - [h]A - R)` is
  the identity. A key with a torsion component (a prime-order point plus a
  small-order point) verifies the same signatures as the clean key, so one
  secret key corresponds to up to `cofactor` accepted public keys, and
  small-order keys pass too. A circuit that derives an identity, a
  membership leaf or a nullifier from `A.X, A.Y` lets one key holder appear
  as several identities.
- **FP:** The identity is derived from something unique per secret (for example
  a hash of the secret proven in-circuit), or the circuit checks `A` on the
  curve and clears the cofactor / checks prime-order subgroup membership
  before hashing the key.
- **Source:** `gnark/std/signature/eddsa/eddsa.go` (`Verify` / `IsValid`: no curve or subgroup check on `A` or `R`; checked at v0.14.0 and v0.16.4)
- **Seed:** FG-SIGNATURE
- **PoC:** T-INVALID-ASSIGNMENT

**V-E3. ECDSA message assumed to be already hashed and reduced**

- **D:** `ecdsa` verification states "We assume that the message msg is already
  hashed to the scalar field." If the circuit passes raw message data, a hash
  computed outside the circuit and supplied as a free witness, or a digest
  reduced differently from the signer, the proof no longer shows that the
  signer signed the intended message.
- **FP:** The message hash is computed in-circuit from the bound message (or is a
  public input the contract recomputes), and reduction mod n matches the signing
  library.
- **Source:** `gnark/std/signature/ecdsa/ecdsa.go` (`Verify` doc comment)
- **Seed:** FG-SIGNATURE
- **PoC:** T-INVALID-ASSIGNMENT

**V-E4. Points used without curve or subgroup checks**

- **D:** Public keys, signature points, proof points or pairing inputs supplied
  as witnesses are used in additions, scalar multiplications or pairings without
  `AssertIsOnCurve`, `AssertIsOnG1` / `AssertIsOnG2` or a subgroup check. Points
  off the curve or outside the prime-order subgroup make group-law formulas and
  pairings compute meaningless results that can still satisfy the final
  equation. In gnark's in-circuit Groth16 verifier the subgroup checks on proof
  points run only with `WithSubgroupCheck()`.
- **FP:** Every external point is checked once at the boundary, or it is a
  constant.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj; `gnark/std/recursion/groth16/verifier.go` (`forceSubgroupCheck`, `WithSubgroupCheck` in `opts.go`); `gnark/std/algebra/emulated/sw_bn254/pairing.go` (`AssertIsOnG2`)
- **Seed:** grep: `Pair\(|ScalarMul\(|AddUnified\(|\.Add\(&`
- **PoC:** T-INVALID-ASSIGNMENT

**V-E5. Exceptional cases in curve formulas (infinity, P = Q, P = -Q)**

- **D:** Incomplete addition formulas divide by `x2 - x1`. With
  `algopts.WithIncompleteArithmetic()`, or in hand-written code, inputs equal to
  each other, opposite, or at infinity make the formula unsatisfiable
  (completeness) or let the prover pick the result (soundness). gnark made
  emulated curve arithmetic complete by default in v0.15.0 and later fixed
  point-at-infinity handling in pairings and the in-circuit Groth16 verifier.
- **FP:** Complete formulas (the default in gnark ≥ v0.15.0), or the exceptional
  inputs are excluded by constraints.
- **Source:** `gnark/std/algebra/algopts/algopts.go` (`WithIncompleteArithmetic`); `gnark/CHANGELOG.md` v0.15.0 "make elliptic curve arithmetic complete by default (#1751)", v0.16.4 "recursion: use complete addition for K[0] in the groth16 verifier (#1843)", "sw_bw6761: handle a G1 point at infinity in the Miller loop (#1850)"; zkSecurity zk-skills circom-auditor V-C3 https://github.com/zksecurity/zk-skills
- **Seed:** grep: `WithIncompleteArithmetic|AddUnequal|Double\(`
- **PoC:** T-INVALID-ASSIGNMENT

**V-E6. Pairing or Miller loop on a degenerate input (Q = 0)**

- **D:** A pairing-product check `e(P1, Q1)·e(P2, Q2) == 1` that accepts a zero
  (infinity) point lets the prover cancel a term. GHSA-3mvx lists a Miller-loop
  issue with `Q = 0`, and gnark v0.16.0 fixed a precomputation whose return value
  was discarded. A verifier gadget built on such a pairing check can accept
  proofs or signatures whose components the prover set to zero.
- **FP:** gnark ≥ v0.16.2, and points that must be non-trivial are asserted
  non-zero before pairing.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65; `gnark/CHANGELOG.md` v0.16.0 "do not discard returned value in Miller loop precomputelines (#1786)"
- **Seed:** inventory: stack advisories; grep: `Pair\(|PairingCheck\(|MillerLoop\(`
- **PoC:** T-INVALID-ASSIGNMENT

**V-E7. Scalar-multiplication decomposition edge cases (top bit, zero scalar)**

- **D:** Windowed or comb scalar multiplication treats the top window or the
  zero scalar specially. GHSA-3mvx lists an unconstrained "comb top bit". When
  the special case is computed by a hint or not covered by the constraints,
  `[s]P` can be replaced by `[s ± 2^k]P` or by the identity.
- **FP:** gnark ≥ v0.16.2, and user scalar multiplications either use the std
  gadgets or constrain the full scalar decomposition, including the top bit and
  `s = 0`.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65; zkSecurity zk-skills circom-auditor V-C4 "EC scalar s = 0 accepted" https://github.com/zksecurity/zk-skills
- **Seed:** inventory: stack advisories; grep: `ScalarMul|JointScalarMul|MultiScalarMul`
- **PoC:** T-HINT-OVERRIDE
