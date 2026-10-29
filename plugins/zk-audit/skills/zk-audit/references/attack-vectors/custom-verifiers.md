# Attack vectors: hand-written and non-gnark verifiers

Slice: Solidity verifiers that gnark did not generate, or that were edited
after generation: snarkjs and ZoKrates templates, hand-rolled Groth16,
PLONK and KZG verifiers in assembly, Halo2 and Barretenberg verifiers, and
wrappers around SP1 or RISC Zero gateways. 9 vectors, V-CV1–V-CV9. The
inventory routes this slice (shard `V-custom`) when it finds a verifier whose
generator is not gnark (`contracts.verifiers[].generator`).

Mantra: **a verifier is the Fiat-Shamir transcript, the precompile calls and
the range checks it makes, nothing more. Read every one.**

---

**V-CV1. Fiat-Shamir transcript omits the statement, the VK or a commitment**

- **D:** A challenge is hashed from part of what it must bind: public inputs,
  the verifying key or the proof's commitments are not absorbed before the
  challenge is squeezed. The prover picks the free values after seeing the
  challenge and forges proofs ("Frozen Heart", weak Fiat-Shamir).
- **FP:** Every challenge is derived from a transcript that absorbed, in
  order, the VK (or its hash), every public input and every prover message
  before it, as the protocol's paper specifies.
- **Source:** https://blog.trailofbits.com/2022/04/18/the-frozen-heart-vulnerability-in-plonk/; https://eprint.iacr.org/2023/691; https://reports.zksecurity.xyz/reports/renegade/ (#05 VKey not absorbed in Fiat-Shamir); https://github.com/0xPARC/zk-bug-tracker#plonk-1
- **Seed:** inventory: contracts.verifiers (generator not gnark); grep: `keccak256\(|sha256\(|mstore\(.*(gamma|beta|alpha|zeta|nu|u)`
- **PoC:** T-ANALYSIS

**V-CV2. Challenge derived from a truncated or partial state**

- **D:** The verifier hashes only the first 32 bytes, a fixed-length prefix,
  or a stale copy of the transcript state for a later challenge (the KZG
  batching randomness, the opening challenge). Values outside the hashed
  range stay free, and a third party can derive a second valid proof for
  the same statement ("Last Challenge").
- **FP:** Each challenge hashes the whole current state, and the length
  passed to the hash covers every absorbed word.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6; https://eprint.iacr.org/2024/398
- **Seed:** grep: `keccak256\(\s*\w+\s*,\s*0x20\s*\)`; manual (length of every hash input)
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV3. Precompile call success or output not checked**

- **D:** `staticcall` to ecAdd (0x06), ecMul (0x07), ecPairing (0x08) or
  modexp (0x05) fails on invalid input (a point off the curve, a wrong
  length) and returns `success = 0` without writing the output. A verifier
  that ignores `success`, or reads an output buffer that already held a
  "valid" value, accepts proofs whose points the precompile rejected.
- **FP:** Every precompile call is followed by a revert on `iszero(success)`
  (or folded into one success flag that is checked before returning), and
  the pairing result word is read from a buffer the call just wrote.
- **Source:** https://github.com/ethereum/EIPs/blob/master/EIPS/eip-196.md; https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md; `gnark/backend/plonk/bn254/solidity.go` (`error_verify` after every failed `staticcall`)
- **Seed:** inventory: contracts.verifiers[].precompiles; grep: `staticcall\(`
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV4. Pairing input has the wrong shape**

- **D:** The input to ecPairing has the wrong number of pairs, a point that
  should be negated is not (or both are), G1 and G2 or the Fp2 coefficient
  order are swapped, or the input length is computed from attacker-supplied
  data. EIP-197 returns one for an empty input, and identity points make
  their pair vanish, so a malformed check can pass for any proof.
- **FP:** The pairing checks exactly the protocol's equation (Groth16:
  `e(-A, B)·e(α, β)·e(L, γ)·e(C, δ) = 1`, four pairs, 768 bytes), with
  constant length and identity points rejected or provably harmless.
- **Source:** https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md (empty input returns one); https://github.com/0xPARC/zk-bug-tracker#aztec-2 (identity points make the PLONK pairing pass); https://github.com/cryptosubtlety/00/blob/main/00.pdf
- **Seed:** grep: `staticcall\([^,]*,\s*(0x0*8|8|PRECOMPILE_VERIFY)`; manual (count pairs, check negation)
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV5. Public inputs not checked to be below the scalar field order**

- **D:** The verifier multiplies the input by a VK point without requiring
  `input < r`. ecMul reduces the scalar, so `x` and `x + r` verify with the
  same proof. A caller that keys state on the input (a nullifier, a root,
  an amount) accepts the same proof again under a second key.
- **FP:** Every input is checked `< r` (revert otherwise) before use, or
  the caller reduces every input before it is stored or compared.
- **Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-33252 (snarkjs Groth16 verifier, double spend); https://github.com/0xPARC/zk-bug-tracker#semaphore-1; https://reports.zksecurity.xyz/reports/risc0-solana-contracts/ (#00 Groth16 verifier reduces public inputs)
- **Seed:** inventory: contracts.verifiers (generator not gnark); grep: `SNARK_SCALAR_FIELD|r_mod|R_MOD|checkField`
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV6. Proof points not checked: coordinates `< q`, on the curve, not the identity**

- **D:** The verifier negates or hashes proof points without checking that
  coordinates are reduced (`< q`) and on the curve. `(x, y)` and
  `(x, y + q)` hash to different transcripts but the precompile sees one
  point; a negation `q - y` of an unreduced `y` underflows. Identity
  points (zero) can satisfy checks the protocol never meant to pass.
- **FP:** Every proof coordinate is range-checked `< q` before it is hashed
  or negated, and the precompile's on-curve check runs on every point that
  enters the pairing (a failed call reverts, V-CV3).
- **Source:** https://reports.zksecurity.xyz/reports/risc0-solana-contracts/ (#03 point negation only sound for reduced points); https://github.com/0xPARC/zk-bug-tracker#aztec-2
- **Seed:** grep: `P_MOD|PRIME_Q|q_mod|sub\(\s*(P|q)`; manual
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV7. Proof encoding is malleable: lengths, trailing bytes, non-canonical fields**

- **D:** The verifier reads the proof from calldata without pinning its
  length, accepts trailing bytes, accepts non-canonical encodings, or takes
  the number of public values from the proof. The same statement has many
  accepted proof byte strings, so a proof hash is not an identifier, and an
  unpinned length can shift which words are read as which values.
- **FP:** The proof length and the public-input count are constants checked
  first, every field element is canonical, and no state is keyed on proof
  bytes.
- **Source:** https://reports.zksecurity.xyz/reports/openvm/ (#05 non-canonical proof encodings, #06 trailing bytes accepted, #08 unpinned public values length); https://reports.zksecurity.xyz/reports/starknet-integrity/ (#04 unchecked FRI commitments length)
- **Seed:** grep: `proof\.length|calldataload\(|_proof\.offset`
- **PoC:** T-FOUNDRY-MALLEATE

**V-CV8. Assembly verifier breaks memory safety**

- **D:** Hand-written assembly writes scratch data over the free memory
  pointer's region, over Solidity-owned memory, or over inputs it reads
  later; reuses one buffer for a precompile's input and output and then
  reads a stale word; or marks a block `memory-safe` when it is not, so the
  optimiser moves Solidity memory under it. A wrong word read from memory
  becomes the challenge or the pairing result.
- **FP:** Every buffer is allocated from the free memory pointer (or the
  scratch space 0x00–0x3f only), the pointer is updated, and no word is read
  after a call that may have overwritten it.
- **Source:** https://github.com/ethereum/solidity/blob/develop/docs/assembly.rst (Memory Safety); `gnark/backend/plonk/bn254/solidity.go` (explicit `mem` offsets from the free memory pointer)
- **Seed:** grep: `assembly\s*(\("memory-safe"\))?\s*\{|mload\(0x40\)`
- **PoC:** T-ANALYSIS

**V-CV9. Wrapper does not bind the program, the VK or the public values**

- **D:** A contract that verifies through a gateway (SP1, RISC Zero) or an
  aggregation wrapper passes a program or image id from storage that an
  unprivileged caller can choose, does not compare the decoded public values
  with the values it acts on, or lets the wrapper skip an equality the inner
  proof needs. The proof is valid, for another program or another statement.
- **FP:** The program id or VK hash is a constant (or owner-set, then T1),
  and every value the contract uses is decoded from the verified public
  values, not from separate calldata.
- **Source:** https://github.com/succinctlabs/sp1-contracts/blob/main/README.md (verifyProof(programVKey, publicValues, proofBytes)); https://reports.zksecurity.xyz/reports/zklighter-wrapper/ (#00 and #01 equalities not enforced in the wrapper)
- **Seed:** inventory: contracts.verify_calls[].target (gateway interfaces); grep: `programVKey|imageId|publicValues|journalDigest`
- **PoC:** T-FOUNDRY-VERIFIER
