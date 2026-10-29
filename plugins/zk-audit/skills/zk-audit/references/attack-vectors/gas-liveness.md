# Attack vectors: gas and liveness

Slice: what stops an honest proof from being accepted: verification that
costs more gas than a block holds, unbounded loops and payloads, root
windows that expire or can be flushed, and capacity an attacker can fill.
5 vectors, V-LV1–V-LV5. Prover-side denial of service (crafted keys, slow
hints) is V-PV2 and V-PV3.

Mantra: **a valid proof that cannot be submitted in time is a frozen
withdrawal.**

---

**V-LV1. Verification costs more gas than a block or a relayer allows**

- **D:** gnark's Groth16 Solidity verifier does one `ECMUL` (6 000 gas) and one
  `ECADD` (150 gas) per public input on top of the pairing check
  (34 000 · k + 45 000 gas), and the PLONK verifier's public-input sum and
  commitment handling also grow with the statement. A circuit with thousands
  of public inputs, a batch entry point that verifies many proofs in one
  call, or an on-chain recursion step can exceed the block gas limit or the
  cap a relayer or bundler applies; then no honest proof is ever accepted.
- **FP:** The verification gas measured for the production public-input
  count, plus everything else in the transaction, stays well under the block
  gas limit and the relayer's cap; large statements are hashed into one
  public input (the circuit recomputes the hash).
- **Source:** `gnark/backend/groth16/bn254/solidity.go` (`publicInputMSM`: one `PRECOMPILE_MUL` call per public input); `gnark/backend/plonk/bn254/solidity.go` (`sum_pi_wo_api_commit`); https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1108.md (alt_bn128 gas costs)
- **Seed:** inventory: contracts.verifiers[].nb_public; inventory: circuits[].witness.nb_public
- **PoC:** T-FOUNDRY-VERIFIER

**V-LV2. Unbounded loop over caller-supplied proofs, inputs or a growing array**

- **D:** A batch function loops over a caller-supplied array of proofs or
  public inputs, or a function loops over a storage array that grows with use
  (all roots, all commitments, all members). Once the array is large enough,
  the call exceeds the block gas limit and the function, sometimes the only
  exit path, is bricked.
- **FP:** Every loop has a constant bound, or a caller-supplied bound checked
  against a constant, and no exit path iterates over state that grows
  without limit.
- **Source:** SWC-128 "DoS With Block Gas Limit" https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-128.md
- **Seed:** inventory: contracts.verify_calls (inside a loop); grep: `for \(.*\.length`
- **PoC:** T-FOUNDRY-VERIFIER

**V-LV3. Proof or calldata size not bounded before work starts**

- **D:** A relayer, prover API or contract takes a proof, a public-input array
  or an aggregate as bytes and decodes it, copies it or allocates for it
  before checking its length. An attacker sends a huge or crafted payload and
  exhausts memory or gas; for an off-chain service this takes it down for
  every user, for a contract it makes the call fail or cost more than needed.
- **FP:** Fixed-size arguments (`uint256[8]`, `uint256[N]`), gnark's PLONK
  verifier's `check_proof_size`, and services that cap request and slice
  sizes before decoding (gnark ≥ v0.11.1 for its own key and proof readers).
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g (CVE-2024-50354); zkSecurity, OpenVM audit, finding #0f "Proof decoding allocates vectors of untrusted size" (Low) https://reports.zksecurity.xyz/reports/openvm/; `gnark/backend/plonk/bn254/solidity.go` (`check_proof_size`)
- **Seed:** FG-UNTRUSTED-DESERIALIZE; grep: `bytes calldata proof`
- **PoC:** T-DOS

**V-LV4. Root history window lets roots expire or be flushed (stale root)**

- **D:** The contract accepts a proof only against one of the last N roots
  (a ring buffer) or against a root younger than a duration. Every insert
  pushes a root. A proof built against a root that leaves the window before
  the transaction lands reverts. If anyone can insert (a public deposit), an
  attacker who sees a pending withdrawal front-runs it with N inserts and
  evicts its root; when the attacker can withdraw its own deposits again, the
  griefing costs gas only and repeats. A window that is too long has the
  opposite problem: removed members keep proving against old roots.
- **FP:** The window is large compared with the insert rate an attacker can
  afford (each insert costs a non-refundable fee or a long lock), inserts are
  batched or rate-limited, the client re-proves against the latest root on
  revert, or roots are time-bounded with a duration longer than inclusion
  delays and shorter than the revocation requirement.
- **Source:** Tornado Cash `MerkleTreeWithHistory` (`ROOT_HISTORY_SIZE = 30`, `isKnownRoot`) https://github.com/tornadocash/tornado-core/blob/1ef6a263ac6a0e476d063fcb269a9df65a1bd56a/contracts/MerkleTreeWithHistory.sol; Semaphore v4 (`merkleTreeDuration`, `Semaphore__MerkleTreeRootIsExpired`) https://github.com/semaphore-protocol/semaphore/blob/v4.14.5/packages/contracts/contracts/Semaphore.sol
- **Seed:** inventory: contracts.state_vars (kind root); grep: `(?i)ROOT_HISTORY|rootHistory|isKnownRoot|Duration`
- **PoC:** T-FOUNDRY-STALE-ROOT

**V-LV5. Fixed capacity an attacker can fill**

- **D:** The tree has a fixed depth, a batch or block circuit has a fixed number
  of slots, or a queue has a maximum length, and anyone can consume capacity
  cheaply. When the tree is full, deposits stop; when a block's slots or
  operation counters can be exhausted or bypassed, priority operations such
  as withdrawals are denied.
- **FP:** Capacity is far above any affordable fill rate, filling it costs
  more than it harms, or there is a migration path (a new tree, a forced
  inclusion queue) that the circuit and the contract both enforce.
- **Source:** Tornado Cash `MerkleTreeWithHistory` ("Merkle tree is full. No more leaves can be added") https://github.com/tornadocash/tornado-core/blob/1ef6a263ac6a0e476d063fcb269a9df65a1bd56a/contracts/MerkleTreeWithHistory.sol; zkSecurity, zkLighter block audit, finding #01 "On-chain operation count can bypass the block limit, leading to denial of L1 withdrawals" (High) https://reports.zksecurity.xyz/reports/zklighter-block/
- **Seed:** inventory: circuits[].witness (fixed-size arrays); grep: `(?i)(depth|levels|max(Batch|Ops|Size))`
- **PoC:** T-FOUNDRY-STALE-ROOT
