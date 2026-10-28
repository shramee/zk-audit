# Attack vectors: hashes and Merkle proofs

Slice: `std/hash/mimc`, `std/hash` (Merkle-Damgård hashers), Poseidon2,
`std/accumulator/merkle`, `std/recursion` wrapped hash, SHA-2 / SHA-3 / Keccak
gadgets, and hand-written Merkle paths. 7 vectors, V-M1–V-M7.

Mantra: **a hash gadget proves "these field elements hash to that digest", not
"this is the protocol object I meant".** Length, domain and position are the
caller's job.

---

**V-M1. MiMC used as a keyed hash or over extensible input**

- **D:** gnark's MiMC uses the Miyaguchi-Preneel construction, which is open to
  length extension. If `H(secret ‖ data)` with a public digest is used as a MAC
  or a commitment, someone without the secret can compute
  `H(secret ‖ data ‖ more)` from the digest. Circuits that hash
  different-length inputs with the same hasher, without a length or domain tag,
  are exposed in the same way.
- **FP:** The input length is fixed by the circuit for each use and no secret
  prefix is treated as a key, or a domain / length tag is the first element
  hashed.
- **Source:** zkSecurity gnark-std audit finding 06 ("MiMC Implementation Is Vulnerable To Length-Extension Attacks"), documented in https://github.com/Consensys/gnark/pull/1198; https://reports.zksecurity.xyz/reports/consensys-gnark-std/
- **Seed:** FG-MIMC
- **PoC:** T-INVALID-ASSIGNMENT

**V-M2. No domain separation between leaves, nodes or protocols**

- **D:** `std/accumulator/merkle` hashes leaves and internal nodes with the same
  hasher and no domain separation (`leafSum` / `nodeSum`: "Without domain
  separation"). The same hasher used for nullifiers, commitments and tree
  nodes lets a value computed for one purpose be presented as another, for
  example an internal node as a leaf commitment, or a commitment as a
  nullifier.
- **FP:** Each use hashes a distinct constant tag first, or the inputs have
  disjoint, enforced arities that make cross-use impossible.
- **Source:** `gnark/std/accumulator/merkle/verify.go` (`leafSum`, `nodeSum` comments)
- **Seed:** FG-MERKLE
- **PoC:** T-INVALID-ASSIGNMENT

**V-M3. Merkle leaf not bound to the data it should commit to**

- **D:** In `MerkleProof.VerifyProof(api, h, index)`, "the actual leaf value must
  be provided as mp.Path[0]". If `Path[0]` is a free witness, and not
  constrained to equal `H(commitment preimage)` computed in the same circuit,
  the prover proves membership of any existing leaf without knowing its
  preimage, or of an internal value.
- **FP:** `Path[0]` is assigned from (or asserted equal to) a hash computed
  in-circuit from the secret the protocol requires.
- **Source:** `gnark/std/accumulator/merkle/verify.go` (`VerifyProof` doc comment)
- **Seed:** FG-MERKLE
- **PoC:** T-INVALID-ASSIGNMENT

**V-M4. Merkle root not public, or not tied to the contract's root**

- **D:** The root is a secret witness, or a public input the contract never
  compares with its root set. The prover then builds a private tree that
  contains its own leaf and proves membership in it.
- **FP:** `RootHash` is a public input and the contract checks it against its
  stored root or root history before accepting the proof.
- **Source:** `gnark/std/accumulator/merkle/verify.go` (`RootHash` field, equality assertion with `mp.RootHash`)
- **Seed:** FG-MERKLE; inventory: binding-table (root row)
- **PoC:** T-FOUNDRY-VERIFIER

**V-M5. Leaf position not bound (custom Merkle paths)**

- **D:** gnark's gadget derives the left/right order from
  `api.ToBinary(index, depth)`, which binds the index to `depth` bits.
  Hand-written paths often take the direction bits as separate, unconstrained
  witnesses, or ignore the index entirely. Then the same leaf can be proven at
  several positions, and position-dependent logic (one note per slot,
  per-position nullifiers) breaks.
- **FP:** Direction bits are the decomposition of an index that is itself
  bound (public, or part of the nullifier), and each bit is boolean.
- **Source:** `gnark/std/accumulator/merkle/verify.go` (`binLeaf := api.ToBinary(leaf, depth)`); zkSecurity zk-skills circom-auditor V-D2 "Merkle-path / mux selector not boolean-constrained" https://github.com/zksecurity/zk-skills
- **Seed:** manual (any loop that hashes `Path[i]` without `VerifyProof`); FG-SELECTOR
- **PoC:** T-INVALID-ASSIGNMENT

**V-M6. Zero padding makes inputs of different lengths collide**

- **D:** A hasher that buffers input and pads the last block with zeros, without
  encoding the length, hashes `x` and `x ‖ 0` to the same digest. gnark's
  recursion `wrapped_hash` had this property; it was safe for its fixed-length
  challenge use but not as a general hash.
- **FP:** Inputs have a fixed length per use, or the length is absorbed.
- **Source:** zkSecurity gnark-std audit finding 0a ("wrapped_hash Is Not Collision Resistant With Input Of Different Length"), documented in https://github.com/Consensys/gnark/pull/1198; `gnark/std/recursion/wrapped_hash.go`
- **Seed:** grep: `recursion\.New(Short|Hash)|wrapped`
- **PoC:** T-INVALID-ASSIGNMENT

**V-M7. In-circuit hash differs from the off-chain or on-chain hash**

- **D:** The prover service or the contract computes the "same" hash outside
  the circuit (Poseidon2 width and round parameters, MiMC vs Keccak, byte vs
  field-element absorption, endianness). Any mismatch either breaks
  completeness (honest proofs fail) or, worse, lets two parties disagree on
  which object a digest names. gnark itself changed Poseidon2's
  `matMulExternal` indexing in v0.15.0, so digests depend on the gnark version.
- **FP:** A test computes the digest natively (gnark-crypto) and in-circuit for
  the same inputs, and the contract side is checked against the same vectors.
- **Source:** `gnark/CHANGELOG.md` v0.15.0 ("poseidon2: support BN254 widths t=4,8,12,16; fix matMulExternal indexing (#1743)"); `gnark/std/hash/hash.go` (`FieldHasher`)
- **Seed:** manual (find the native counterpart of every in-circuit hash)
- **PoC:** T-COMPLETENESS
