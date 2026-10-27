# Attack vectors: protocol state

Slice: nullifier sets, root histories, membership sets and identities that the
contract or service derives from proofs. 4 vectors, V-PS1–V-PS4. The
protocol-state lens (I3) also checks ordering, atomicity and reentrancy around
verification calls; those checks are in its lens file because they need no
ZK-specific source.

Mantra: **proof bytes are not unique. Never key state on them.**

<!-- V-PS3 and V-PS4 are gnark rewrites of zkSecurity zk-skills circom-auditor V-H3 and V-H6 (MIT, (c) 2026 zkSecurity). -->

---

**V-PS1. Replay protection or nullifier keyed on proof bytes**

- **D:** The contract stores `keccak256(proof)` (or the proof itself) as "used".
  Proofs are not unique: gnark's Groth16 prover samples fresh `r, s` for every
  proof, so an honest prover produces a new valid proof for the same statement
  at will. Third parties can also derive new valid proofs from an observed one
  (for gnark's old PLONK verifier, by the advisory below). The same statement is
  accepted again under a new proof hash.
- **FP:** Replay protection is keyed on a nullifier that is a constrained public
  input, unique per statement, and stored when the proof is accepted.
- **Source:** `gnark/backend/groth16/bn254/prove.go` ("sample random r and s"); https://github.com/Consensys/gnark/security/advisories/GHSA-7p92-x423-vwj6
- **Seed:** inventory: contracts.state_accesses (write of a key derived from `proof`); grep: `keccak256\(proof|keccak256\(abi\.encode\(proof`
- **PoC:** T-FOUNDRY-REPLAY

**V-PS2. Nullifier derived from a signature**

- **D:** The circuit computes the nullifier from `(R, S)` of a signature verified
  in-circuit, or the service derives an identifier from signature bytes. With a
  malleable signature (gnark < v0.14.0: `S + n` verifies), one authorisation
  yields several nullifiers, which is a double spend.
- **FP:** The nullifier is derived from a secret and a context the prover cannot
  vary (for example `H(sk, domain)` with `sk` proven in-circuit), and gnark is
  ≥ v0.14.0.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj (CVE-2025-57801)
- **Seed:** FG-SIGNATURE
- **PoC:** T-INVALID-ASSIGNMENT

**V-PS3. Empty-leaf sentinel accepted as a member**

- **D:** Sparse or incremental trees fill empty slots with a known zero value. If
  the membership circuit does not forbid the sentinel as a leaf (and the leaf is
  not bound to a preimage, V-M3), anyone proves membership of an empty slot, or
  of an identity commitment that hashes to the sentinel.
- **FP:** The circuit asserts `leaf != zeroValue`, or leaves are hashes of
  preimages proven in-circuit whose image cannot equal the sentinel.
- **Source:** zkSecurity zk-skills circom-auditor V-H3 "Sentinel zero leaf admitted as valid membership proof" https://github.com/zksecurity/zk-skills; `gnark/std/accumulator/merkle/verify.go` (leaf is `Path[0]`)
- **Seed:** FG-MERKLE; grep: `(?i)zero(value|leaf|hash)`
- **PoC:** T-INVALID-ASSIGNMENT

**V-PS4. Nullifier without per-context or per-identity binding**

- **D:** A nullifier is `H(secret)` with no action, epoch or contract context, or
  `H(mutable data)` that the holder can vary (formatting, ordering, a second
  key for the same identity, see V-E2). One identity then acts many times, or
  one action is linkable across contexts that should be unlinkable.
- **FP:** The nullifier is `H(secret, context)` with the context public and
  fixed by the contract, and the secret is proven to belong to the registered
  identity.
- **Source:** zkSecurity zk-skills circom-auditor V-H6 "Low-entropy / non-context-binding nullifier" https://github.com/zksecurity/zk-skills
- **Seed:** inventory: binding-table (nullifier row); manual
- **PoC:** T-INVALID-ASSIGNMENT
