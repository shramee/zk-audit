# Attack vectors: commitments, Fiat-Shamir and recursion

Slice: `frontend.Committer` / `api.Compiler()` commitments, `std/multicommit`,
in-circuit challenges, `std/recursion/groth16` and `std/recursion/plonk`
verifiers, and transcripts. 8 vectors, V-CM1–V-CM8.

Mantra: **a challenge is only as binding as what was absorbed before it, and an
inner proof means nothing until its VK and public inputs are bound.**

---

**V-CM1. Groth16 with more than one commitment (gnark < v0.11.0)**

- **D:** gnark's Groth16 commitment extension used the same σ for every
  commitment's proof of knowledge. With two or more commitments a prover can
  fix all but one commitment before choosing the witness, so challenges derived
  from them no longer bind the witness. Any circuit that uses in-circuit
  randomness (log-derivative lookups, range checks with commitments,
  `multicommit`) inherits the problem.
- **FP:** gnark ≥ v0.11.0 with keys regenerated, a single commitment, or the
  PLONK backend.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-q3hw-3gm4-w5cr (CVE-2024-45039)
- **Seed:** FG-COMMIT; inventory: stack advisories
- **PoC:** T-ANALYSIS

**V-CM2. Commitment to private witness values breaks zero knowledge (gnark < v0.11.0)**

- **D:** The Groth16 commitment `c = Σ w_i·b_i` over private values is binding
  but not hiding, and the basis is in the proving key. A verifier who can guess
  the committed values (small balances, a short secret) confirms the guess from
  the proof. The privacy claim of the protocol fails.
- **FP:** gnark ≥ v0.11.0 (which fixed the advisory), or only public or
  high-entropy values are committed.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-9xcg-3q8v-7fq6 (CVE-2024-45040)
- **Seed:** FG-COMMIT; inventory: stack advisories
- **PoC:** T-ANALYSIS

**V-CM3. Derived challenges that are not independent**

- **D:** Deriving many challenges from one commitment by repeated squaring
  (`c, c², c⁴, …`) can converge to 1 in fields where `p - 1` has a large power of
  two. Then the "challenge" is a constant the prover knows in advance, and the
  Fiat-Shamir argument loses its binding. gnark's `multicommit` used this
  scheme; the audit found it practical on the STARK curve field.
- **FP:** Challenges are derived with independent hashing or powers `c^i`, as
  recommended, and gnark is at a version that includes the fix.
- **Source:** zkSecurity gnark-std audit finding 00 ("MultiCommitter Scheme May Converge To Using Constant Challenge 1"), fixed in https://github.com/Consensys/gnark/pull/1212; https://reports.zksecurity.xyz/reports/consensys-gnark-std/
- **Seed:** FG-COMMIT; grep: `api\.Mul\(cmt, cmt\)|Mul\(c, c\)`
- **PoC:** T-ANALYSIS

**V-CM4. Inner verifying key is a free witness**

- **D:** A recursive circuit verifies an inner proof against a VK built with
  `ValueOfVerifyingKey`, and that VK is part of the witness. If the VK is not
  bound to a constant or to a public hash that the outer verifier checks, the
  prover brings its own circuit and VK. It proves anything. With
  `ValueOfVerifyingKeyFixed` on a witness VK the precomputed G2 lines "are not
  constrained to correspond to the point coordinates", which is worse.
- **FP:** The VK field is tagged `gnark:"-"` and set to the expected VK at compile
  time (`ValueOfVerifyingKeyFixed`), or a hash of the VK is a public input pinned
  by the contract, or `SwitchVerificationKey` picks from a constant list.
- **Source:** `gnark/std/recursion/groth16/verifier.go` (`ValueOfVerifyingKey`, `ValueOfVerifyingKeyFixed` doc comments)
- **Seed:** FG-VK-AS-WITNESS
- **PoC:** T-ANALYSIS

**V-CM5. Inner proof's public inputs not bound to the outer statement**

- **D:** `AssertProof(vk, proof, witness)` proves "some statement with these inner
  public inputs is true". If the inner public inputs are free witnesses, not
  equal to outer public inputs or to values computed in the outer circuit, the
  outer proof only says that *some* valid inner proof exists. An old or
  unrelated proof then satisfies it.
- **FP:** Every inner public input is asserted equal to an outer public input or
  to a value derived in-circuit from bound data.
- **Source:** `gnark/std/recursion/groth16/verifier.go` (`AssertProof`, `ValueOfWitness`)
- **Seed:** grep: `AssertProof\(|ValueOfWitness`
- **PoC:** T-ANALYSIS

**V-CM6. Flag-based proof verification whose result is not asserted**

- **D:** `IsValidProof` returns a variable instead of asserting. If the result is
  only used to gate optional logic, ignored, or combined with a prover-chosen
  flag, the outer proof is valid when the inner proof is invalid.
- **FP:** The result is asserted to 1, or it gates something whose disabled
  branch is safe and independently bound.
- **Source:** `gnark/std/recursion/groth16/verifier.go` (`IsValidProof`); `gnark/CHANGELOG.md` v0.15.0 "implement flag based recursive groth16 and EdDSA check (#1647)"
- **Seed:** FG-DISCARDED-PREDICATE; grep: `IsValidProof\(`
- **PoC:** T-INVALID-ASSIGNMENT

**V-CM7. Fiat-Shamir transcript omits a value the prover can influence**

- **D:** A non-interactive argument must absorb every value that defines the
  statement before deriving challenges: public inputs, commitments, domain
  parameters. If one is left out, the prover can adapt it after seeing the
  challenge. Known gnark-adjacent cases: the FFT generator missing from a
  permutation argument's transcript, and the PLONK Solidity verifier's batch
  challenge derived from only part of the state (GHSA-7p92, the "Last
  Challenge" attack).
- **FP:** The transcript order and content match the paper, and each value
  appears before the challenge that depends on it.
- **Source:** Least Authority, gnark arithmetic and GKR audit, Issue D "Permutation NIZK Does Not Include FFT Generator in the Transcript" (`gnark/audits/2024-09 - Least Authority - arithm and GKR.pdf`), https://leastauthority.com/blog/gnark-cryptographic-library/; https://eprint.iacr.org/2024/398
- **Seed:** manual (custom transcripts; `fiat-shamir` package use)
- **PoC:** T-ANALYSIS

**V-CM8. In-circuit verifier built with incomplete arithmetic**

- **D:** In-circuit Groth16 verification computes `K[0] + Σ x_i·K[i]`. With
  incomplete addition, crafted public inputs that make an intermediate sum equal
  to the next term (or to its negation) break the formula. gnark switched to
  complete addition for `K[0]` in v0.16.4 and deprecated
  `WithCompleteArithmetic` because complete arithmetic is now the default.
- **FP:** gnark ≥ v0.16.4, or an older version with complete arithmetic for
  every public-input MSM step.
- **Source:** `gnark/CHANGELOG.md` v0.16.4 "recursion: use complete addition for K[0] in the groth16 verifier (#1843)"; `gnark/std/recursion/groth16/opts.go` (`WithCompleteArithmetic` deprecation note)
- **Seed:** inventory: stack versions; grep: `recursion/groth16`
- **PoC:** T-ANALYSIS
