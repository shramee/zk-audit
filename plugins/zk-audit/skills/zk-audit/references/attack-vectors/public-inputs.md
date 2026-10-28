# Attack vectors: public inputs and binding

Slice: fields tagged `gnark:",public"`, the public-witness vector, the
contract code that builds `uint256[] input`, and what the statement is bound
to. 7 vectors, V-PI1–V-PI7. Start every review of this slice from
`binding-table.md`.

Mantras: **the public-witness order is the struct walk order.** **Ask what a
proof is bound to: sender, recipient, chain, contract, nonce, epoch. Every
missing item is a replay or front-running path.**

<!-- V-PI4 and V-PI5 are gnark/Solidity rewrites of zkSecurity zk-skills circom-auditor V-H1 and V-H6 (MIT, (c) 2026 zkSecurity). -->

---

**V-PI1. Contract input order differs from the public-witness order**

- **D:** gnark orders public inputs by walking the circuit struct: field order,
  nested structs depth-first, arrays element by element, embedded fields inline,
  with tag names but not tag order. The contract builds `input[i]` by hand. A
  reordered, inserted or removed field (in a refactor or a gnark tag change)
  silently shifts the meaning of every later index. Then a nullifier is checked
  as a root, a recipient as an amount, and so on. Proofs still verify because
  the verifier only sees numbers.
- **FP:** The contract's assignment order matches the inventory's
  public-witness order index by index, and a test proves with gnark and verifies
  on-chain with distinct values in every slot.
- **Source:** `gnark/frontend/schema/walk.go` (walk order, embedded fields, `_` name joining); `gnark/frontend/compile.go` ("add public inputs first to compute correct offsets")
- **Seed:** inventory: binding-table
- **PoC:** T-FOUNDRY-VERIFIER

**V-PI2. Public input that no constraint uses**

- **D:** A public input that appears in no constraint is not bound by the proof:
  any value verifies. gnark refuses to compile such circuits unless
  `frontend.IgnoreUnconstrainedInputs()` is passed. The weaker form is a public
  input used only in a constraint that does not pin it (for example inside a
  discarded `IsZero`, or multiplied by a zero flag). The contract then trusts a
  value the prover chose freely.
- **FP:** Every public input appears in at least one constraint that determines
  it given the rest of the witness, and `IgnoreUnconstrainedInputs` is not used
  in production compilation.
- **Source:** `gnark/frontend/compile.go` (`IgnoreUnconstrainedInputs`: "should not be used in production settings"); `gnark/frontend/cs/r1cs/builder.go` ("circuit has unconstrained inputs"); zkSecurity zk-skills circom-auditor V-H4 https://github.com/zksecurity/zk-skills
- **Seed:** FG-IGNORE-UNCONSTRAINED-INPUTS, FG-DISCARDED-PREDICATE
- **PoC:** T-INVALID-ASSIGNMENT

**V-PI3. Public inputs ≥ r alias in custom verifiers or callers**

- **D:** A public input is a field element, but the contract passes `uint256`.
  gnark's generated Groth16 verifier rejects inputs ≥ r with
  `PublicInputNotInField`. A custom or modified verifier that reduces inputs
  mod r, or a caller that reduces before storing, maps `x` and `x + r` to the
  same statement. Then two different on-chain values (two nullifiers, two
  recipients) share one proof.
- **FP:** The generated gnark verifier is used unmodified, and the caller
  stores exactly the value it passed to the verifier.
- **Source:** `gnark/backend/groth16/bn254/solidity.go` (`publicInputMSM`: "Reverts with PublicInputNotInField if the input is not in the field")
- **Seed:** inventory: contracts.verifiers (kind), binding-table
- **PoC:** T-FOUNDRY-VERIFIER

**V-PI4. Proof not bound to the caller or recipient (front-running)**

- **D:** The statement covers protocol state (root, nullifier, amount) but not
  who may use the proof or who receives the funds. Anyone who sees the
  transaction in the mempool submits the same proof first, with their own
  address as recipient where the contract takes it as a separate argument.
- **FP:** The recipient, or `msg.sender`, is a public input constrained in the
  circuit (for example hashed into the nullifier or an intent hash) and the
  contract passes exactly that value.
- **Source:** zkSecurity zk-skills circom-auditor V-H1 "Proof not bound to caller intent" https://github.com/zksecurity/zk-skills
- **Seed:** inventory: binding-table (bound-to column)
- **PoC:** T-FOUNDRY-REPLAY

**V-PI5. Proof not bound to chain, contract or epoch (cross-domain replay)**

- **D:** The same circuit and VK are deployed on several chains or contracts, or
  across protocol epochs. Without `chainid`, the verifying contract's address,
  or an epoch / nonce in the statement, a proof accepted in one domain is
  accepted in the other, and nullifiers stored per contract do not stop it.
- **FP:** The statement includes a domain identifier the contract supplies
  itself (`block.chainid`, `address(this)`, current epoch), or nullifiers are
  global across all deployments.
- **Source:** zkSecurity zk-skills circom-auditor V-H6 "Low-entropy / non-context-binding nullifier" https://github.com/zksecurity/zk-skills
- **Seed:** inventory: binding-table (bound-to column)
- **PoC:** T-FOUNDRY-REPLAY

**V-PI6. Encoding mismatch between the circuit and the contract**

- **D:** The contract converts values to field elements in one way (an address
  cast `uint256(uint160(a))`, a hash truncated or shifted to fit, signed
  amounts, packed bytes in big-endian) and the circuit or prover in another.
  Either honest proofs fail, or the circuit proves a statement about a value the
  contract interprets differently. gnark fixed an endianness mismatch in its own
  KZG point-evaluation precompile circuit.
- **FP:** A round-trip test encodes each value with the contract's code, proves
  with gnark and verifies, including boundary values (max address, values near
  r, zero).
- **Source:** `gnark/CHANGELOG.md` v0.15.0 "use the little-endian representation for serialized values in KZG Pointeval precompile (#1614)"; zkSecurity zk-skills circom-auditor V-H14 "Inter-circuit / circuit ↔ host data-format mismatch" https://github.com/zksecurity/zk-skills
- **Seed:** inventory: binding-table (contract source expr)
- **PoC:** T-FOUNDRY-VERIFIER

**V-PI7. Slice-typed public inputs whose length is set at compile time**

- **D:** A `[]frontend.Variable` public field gets its length from the value
  passed to `frontend.Compile`; an empty slice is skipped with only a warning.
  The contract hard-codes a count. If the key-generation code and the deployed
  contract disagree on the length, every index after the slice shifts, or the
  slice vanishes from the statement.
- **FP:** Public inputs are fixed-size arrays, or the compile code, the VK and
  the contract are generated from one constant, and a test checks the count.
- **Source:** `gnark/frontend/schema/walk.go` (`Slice`: "ignoring uninitialized slice")
- **Seed:** inventory: circuits[].witness.public[].kind == slice
- **PoC:** T-FOUNDRY-VERIFIER
