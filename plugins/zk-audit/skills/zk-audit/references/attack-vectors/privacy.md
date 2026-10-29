# Attack vectors: privacy

Slice: what a proof system that promises privacy leaks around the proof:
public inputs, events and calldata, nullifiers and tags, amounts and timing,
relayers and indexers, and the services that see the witness. 7 vectors,
V-PR1–V-PR7. The proof itself is zero-knowledge; these vectors are about
everything next to it. Related vectors in other slices: V-CM2 (Groth16
commitments to private values, gnark < v0.11.0), V-G6 (a privacy flag that
gates only half a comparison), V-PS4 (nullifier without context binding),
V-PV5 (witness values in logs).

Mantra: **zero knowledge covers the proof, not the public inputs, the
calldata, the events, the fee payer or the relayer.**

<!-- V-PR3 is a gnark rewrite of zkSecurity zk-skills circom-auditor V-H2 (MIT, (c) 2026 zkSecurity). -->

---

**V-PR1. Secret value exposed through a public input, event or calldata**

- **D:** A value the protocol claims to hide is a public input, is emitted in
  an event, is passed in calldata next to the proof, or is a public input that
  is an invertible or low-entropy function of it (an amount, a leaf index, a
  balance, an expiry, `H(amount)` over a small range). Anyone reading the
  chain recovers it or shrinks the anonymity set with it.
- **FP:** Every public input, event field and calldata argument is either
  meant to be public (the spec says so) or a hiding commitment with fresh
  randomness the prover keeps secret.
- **Source:** zkSecurity, intmax zERC20 audit, finding #03 "Nova Proof Leaks Last Leaf Index in Calldata" (Low) https://reports.zksecurity.xyz/reports/intmax-zerc20-1/; zkSecurity, ZK Email audit, finding #04 "The reveal array leaks inputs in a non-match" (Medium) https://reports.zksecurity.xyz/reports/zkemail/; zkSecurity, Demox Aleo standard programs audit, finding #07 "transfer_private Function May Leak Information with authorized_until Field" (Medium) https://reports.zksecurity.xyz/reports/demox-aleo-standard-programs/
- **Seed:** inventory: circuits[].witness.public; inventory: contracts.verify_calls; grep: `emit .*\((.*(amount|value|index|balance|secret|note))`
- **PoC:** T-LINKAGE

**V-PR2. Nullifier or tag computable from public data**

- **D:** The nullifier (or any per-user tag) is `H(publicKey)`, `H(address)`,
  `H(email)` or a hash of another value that observers know or can
  enumerate. Anyone recomputes the tag for every candidate and links the
  anonymous action to the identity. A tag must depend on a secret only the
  user holds (a secret key, a note secret), not only on the identity.
- **FP:** The tag is `H(secret, context)` where `secret` is a private input
  the circuit proves is the user's own key or note secret, and no public
  value determines it.
- **Source:** Gupta and Gurkan, "PLUME: An ECDSA Nullifier Scheme for Unique Pseudonymity within Zero Knowledge Proofs" https://eprint.iacr.org/2022/1255; Semaphore v4 circuit (`nullifier <== Poseidon(2)([scope, secret])`) https://github.com/semaphore-protocol/semaphore/blob/v4.14.5/packages/circuits/src/semaphore.circom
- **Seed:** inventory: binding-table (nullifier row); grep: `(?i)nullif.*(Pub|Address|Email|Key)`; manual
- **PoC:** T-LINKAGE

**V-PR3. The same tag or commitment reappears across actions or contexts**

- **D:** A value that is constant per user (an identity commitment, a public
  key, a credential hash, a nullifier without a context input) is a public
  input of every proof the user makes. All of that user's actions are linked
  to each other, and deanonymising one deanonymises all.
- **FP:** Every public per-user value mixes in a per-action or per-context
  input (`scope`, `epoch`, `tokenId`, a fresh randomiser) that the contract
  fixes or checks, and nothing else is repeated across proofs.
- **Source:** zkSecurity zk-skills circom-auditor V-H2 "Static issuer commitment omits per-action variable" https://github.com/zksecurity/zk-skills; Semaphore v4 circuit (`scope` input) https://github.com/semaphore-protocol/semaphore/blob/v4.14.5/packages/circuits/src/semaphore.circom
- **Seed:** inventory: circuits[].witness.public; manual (list public inputs that do not change between two proofs of one user)
- **PoC:** T-LINKAGE

**V-PR4. Amount, timing or fee fingerprints link deposits and withdrawals**

- **D:** The pool accepts arbitrary amounts, lets a withdrawal follow its
  deposit closely, or lets the user choose a fee, gas price or refund value.
  A unique amount, a short deposit-to-withdraw gap or a reused fee value links
  the two sides, and the anonymity set shrinks to the few candidates that
  match. Re-using the deposit address for gas or as the recipient links them
  directly.
- **FP:** Fixed denominations (or amounts hidden inside the statement), a fee
  set by the contract or bounded to a few values, withdrawals paid by a
  relayer to a fresh address, and documentation that tells users to wait.
- **Source:** Béres, Seres, Benczúr and Quintyne-Collins, "Blockchain is Watching You: Profiling and Deanonymizing Ethereum Users" https://arxiv.org/abs/2005.14051; Wu et al., "Tutela: An Open-Source Tool for Assessing User-Privacy on Ethereum and Tornado Cash" https://arxiv.org/abs/2201.06811; Kappos, Yousaf, Maller and Meiklejohn, "An Empirical Analysis of Anonymity in Zcash" https://www.usenix.org/conference/usenixsecurity18/presentation/kappos
- **Seed:** inventory: circuits[].witness.public (amount, value or fee inputs); grep: `(?i)(fee|refund|denomination|amount)`
- **PoC:** T-ANALYSIS

**V-PR5. A relayer, indexer or sequencer sees what links the user**

- **D:** The flow sends the proof's public values (recipient, nullifier,
  fee) and the user's network address to a relayer, or asks an indexer which
  notes belong to the user. The operator learns sender-to-recipient links,
  IPs and timing, can log them, and can censor. The privacy model then holds
  only if that operator is honest, which the trust model rarely says.
- **FP:** Users can run the relayer or indexer themselves or submit
  directly, the documented trust model names the operator, and requests do
  not carry more than the chain will publish anyway.
- **Source:** zkSecurity, intmax zERC20 audit, finding #01 "Indexer Service Can Link Senders to Recipients" (Low) https://reports.zksecurity.xyz/reports/intmax-zerc20-1/; Tornado Cash relayer request schema (proof, root, nullifier hash, recipient, relayer, fee, refund) https://github.com/tornadocash/tornado-relayer/blob/2247730603f2c249f90da0b07058325619435387/src/modules/validator.js
- **Seed:** grep: `(?i)(relayer|indexer|sequencer)`; inventory: roles (kind relayer, sequencer)
- **PoC:** T-ANALYSIS

**V-PR6. The witness leaves the user: delegated provers, services, timing**

- **D:** A prover service, delegated prover or scanner receives the private
  inputs (notes, keys, view keys, amounts) in the clear, logs them, sends them
  to a third party, or proves in time that depends on secret values. Whoever
  operates it, or watches it, learns what the proof hides; a signing key in
  the request also lets them act as the user.
- **FP:** Proving runs on the user's device, or the service receives only
  what it needs, over an encrypted channel, with no logging (V-PV5), and
  proving time does not depend on secrets that matter.
- **Source:** zkSecurity, Aleo synthesizer audit, finding #04 "Proof Delegation Leaks User Signing Key" (High) https://reports.zksecurity.xyz/reports/aleo-synthesizer/; zkSecurity, HumanityLink audit, finding #12 "Beneficiary records and view keys are sent to the delegated prover and scanner in plaintext" (Informational) https://reports.zksecurity.xyz/reports/humanitylink-1/; Tramèr, Boneh and Paterson, "Remote Side-Channel Attacks on Anonymous Transactions" https://eprint.iacr.org/2020/220
- **Seed:** FG-UNTRUSTED-DESERIALIZE; grep: `(?i)(http\.Post|grpc|json\.Marshal\(.*(witness|assignment))`; manual
- **PoC:** T-ANALYSIS

**V-PR7. The real member of an anonymity set is distinguishable**

- **D:** A protocol that hides the sender among decoys (a ring, a set of
  accounts updated together) treats the real member differently: one update
  is not a no-op on the decoys, a public value differs for the real index, or
  the client picks the position with a predictable random source.
- **FP:** Every member of the set gets an update whose public form is
  identical to the real one, the circuit enforces it, and the client draws the
  position from a cryptographic random source.
- **Source:** zkSecurity, Silent Protocol audit, finding #00 "Broken anonymity in zero-fee registration" (High) and finding #07 "Insecure randomness used for anonymity set sender position" (Low) https://reports.zksecurity.xyz/reports/silent2/
- **Seed:** grep: `(?i)(anonymity|ring|decoy|Math\.random|math/rand)`; manual
- **PoC:** T-LINKAGE
