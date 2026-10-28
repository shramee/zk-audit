# Attack vectors: prover service and key handling

Slice: Go code outside `Define`: witness construction, `Setup`, key and proof
serialization, `Prove` / `Verify` options, logging, and dependency versions.
6 vectors, V-PV1–V-PV6.

Mantra: **the circuit can be perfect and the service can still prove the wrong
thing, leak the witness, or fall over.**

---

**V-PV1. Single-party or unsafe setup used for production keys**

- **D:** `groth16.Setup(ccs)` runs a trusted setup in one process; whoever ran it
  knows the toxic waste and can forge proofs for that circuit.
  `test/unsafekzg.NewSRS` creates a KZG SRS "for test purposes only". Keys or
  contracts produced this way in a deploy script, a service start-up, or a
  committed `Verifier.sol` make soundness depend on one machine.
- **FP:** Production Groth16 keys come from an MPC ceremony (gnark's `mpcsetup`
  package or an external ceremony) with a verifiable transcript, and PLONK uses
  a public SRS. Single-party setup appears only in tests.
- **Source:** `gnark/test/unsafekzg/kzgsrs.go` (package doc: "to be use for test purposes only"); `gnark/backend/groth16/groth16.go` (`Setup`)
- **Seed:** FG-DEV-SETUP
- **PoC:** T-ANALYSIS

**V-PV2. Deserializing keys, proofs or witnesses from untrusted input**

- **D:** Before gnark v0.11.1, `ReadFrom` on a crafted verifying key or proof
  allocated attacker-chosen sizes (for example `nbCommitments`) and exhausted
  memory. Services that accept proofs, VKs or witnesses over the network can be
  taken down. `UnsafeReadFrom` skips curve checks by design and must only read
  trusted data.
- **FP:** gnark ≥ v0.11.1, input size limits before deserialization, and
  `UnsafeReadFrom` only on locally generated files.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g (CVE-2024-50354); `gnark/backend/groth16/bn254/marshal.go` (`UnsafeReadFrom`)
- **Seed:** FG-UNTRUSTED-DESERIALIZE
- **PoC:** T-DOS

**V-PV3. Hint that can be made slow by the witness (prover DoS)**

- **D:** Hints run arbitrary Go on prover-supplied inputs. gnark's fake-GLV
  scalar decomposition (v0.12.x) converged very slowly for some inputs, so a
  service that proves on untrusted witnesses could be stalled. Custom hints with
  loops over input-dependent bounds have the same shape.
- **FP:** gnark ≥ v0.13.0 (or gnark-crypto with the fix), and custom hints are
  bounded in time by construction or run with a timeout.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-9fvj-xqr2-xwg8 (CVE-2025-58157); https://github.com/Consensys/gnark/issues/1483
- **Seed:** inventory: hint_functions; inventory: stack advisories
- **PoC:** T-DOS

**V-PV4. Witness built from different data than the contract will check**

- **D:** The service assembles the assignment (Go struct values) from its own
  view of state: a different root, a stale nonce, a recomputed hash, an amount
  in different units. The circuit then proves a statement about that data, and
  the contract checks it against its own values. Honest proofs fail, or the
  service can be steered into proving something the user did not intend.
- **FP:** Every public value in the assignment is read from the same source the
  contract uses, and the service checks the public witness before proving.
- **Source:** zkSecurity zk-skills circom-auditor V-H14 "Inter-circuit / circuit ↔ host data-format mismatch" https://github.com/zksecurity/zk-skills; `gnark/frontend/witness.go` (`NewWitness`, `PublicOnly`)
- **Seed:** manual (trace each `frontend.NewWitness` call back to its data sources)
- **PoC:** T-COMPLETENESS

**V-PV5. Witness values written to logs**

- **D:** `api.Println` prints witness values at solve time ("whose value will be
  resolved at runtime when computed by the solver") through the solver logger.
  Debug prints left in a circuit leak secrets (keys, notes, amounts) to the
  prover's logs. Services that log assignments or serialized witnesses on error
  do the same.
- **FP:** No `api.Println` on secret values in production builds, the solver
  logger is set to `zerolog.Nop()` (`solver.WithLogger`), and the service never
  logs witnesses.
- **Source:** `gnark/frontend/api.go` (`Println` doc comment); `gnark/constraint/solver/options.go` (`WithLogger`)
- **Seed:** grep: `api\.Println\(|Println\(.*(secret|priv|key|witness)`
- **PoC:** T-ANALYSIS

**V-PV6. Prover and verifier configured with different options**

- **D:** Prove and Verify accept options that change the statement or the
  transcript: `backend.WithProverHashToFieldFunction` /
  `backend.WithVerifierHashToFieldFunction`, solver options, Solidity targets.
  If the service's prover and the verifier (Go or Solidity) use different
  options, honest proofs fail, or a check in a test environment does not
  reflect production.
- **FP:** One shared configuration object builds both sides, and an end-to-end
  test proves and verifies with production options.
- **Source:** `gnark/backend/backend.go` (`WithProverHashToFieldFunction`, `WithVerifierHashToFieldFunction`, `WithSolverOptions`)
- **Seed:** FG-HASH-TO-FIELD
- **PoC:** T-COMPLETENESS
