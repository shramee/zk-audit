# Attack vectors: contract review beyond the verifier call

Slice: the Solidity around a ZK system that is not the proof check itself:
deposits and withdrawals, token handling, external calls, signatures,
initialisation and upgrades, accounting, pause switches and identifiers.
11 vectors, V-SA1–V-SA11. Scanned by the `V-contract` shard; the S1 lens
owns the `contract-review` ledger units (one per entry point). The
`solidity-auditor` companion covers this ground more widely when installed
(`references/companions.md`); this slice is the embedded fallback and is
sourced from audits of ZK applications.

Mantra: **a sound proof does not make the token transfer, the signature or
the upgrade around it sound.**

---

**V-SA1. Deposit or registration not bound to the depositor (front-running, account poisoning)**

- **D:** The proof or the call that credits a note, account or wallet does
  not bind the address that pays. Anyone who copies the calldata from the
  mempool deposits into, or claims, the victim's account first: funds are
  stolen when the transfer pulls from a permit or allowance the attacker can
  replay, or the account is poisoned with funds the victim never sent.
- **FP:** The payer (`msg.sender`, the permit owner) is a public input or is
  checked against the account owner, and permits name the exact recipient
  contract and action.
- **Source:** https://reports.zksecurity.xyz/reports/renegade/ (#00 deposits can be stolen by front-runners); https://reports.zksecurity.xyz/reports/aleph-zero-shielder/ (#00 account poisoning in NewAccount and Deposit); https://reports.zksecurity.xyz/reports/tongo/ (#05 fund operation front-running and account poisoning)
- **Seed:** inventory: contracts.entry_points (effects erc20 or eth-out with verify); grep: `permit|transferFrom\(`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA2. Fee-on-transfer, rebasing or non-standard tokens credit more than received**

- **D:** The contract credits the `amount` argument instead of the balance
  it received. A token that takes a fee, rebases, or reports a different
  amount makes the pool owe more than it holds, and the last withdrawers
  cannot exit.
- **FP:** Credit is the balance difference around the transfer, or the
  token list is fixed to tokens known not to do this.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-3/ (#01 fee-on-transfer tokens cause underfunded deposits)
- **Seed:** inventory: contracts.entry_points (effects erc20); grep: `transferFrom\(`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA3. ERC20 transfer return values not checked**

- **D:** `token.transfer` / `transferFrom` are called without checking the
  returned bool, or through an interface that expects a bool from tokens
  that return nothing. A token that returns `false` leaves the transfer
  undone while the contract records it (a deposit credited, a nullifier
  spent with no payout).
- **FP:** SafeERC20 (`safeTransfer`, `safeTransferFrom`) or an explicit
  check of the return data length and value on every call.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-3/ (#03 unchecked ERC20 transfer return values); https://reports.zksecurity.xyz/reports/tongo/ (#08 ERC20 transfer functions do not check return values); https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-104.md
- **Seed:** inventory: contracts.entry_points (effects erc20); grep: `\.transfer(From)?\(`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA4. Reentrancy through ETH sends, token callbacks or hooks**

- **D:** An external call (ETH send, token transfer of an arbitrary or
  hook-bearing token, a callback to the recipient) runs before the contract
  records the nullifier, the balance or the settlement. The callee re-enters
  and repeats the action with the same proof or the same state.
- **FP:** Checks-effects-interactions on every path (state written before the
  call), or a reentrancy guard on every entry point that shares the state.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-atomic-settlement/ (#03 no restriction on ERC-20 token contracts allows reentrant execution); https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-107.md
- **Seed:** inventory: contracts.entry_points (effects eth-out, erc20, external-call or low-level-call without reentrancy-guard); inventory: contracts.state_accesses (write after the call)
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA5. Malleable signatures and `ecrecover` without checks**

- **D:** A signature is verified with bare `ecrecover`: `s` in the upper
  half and `v` 27/28 give a second valid signature for the same message,
  and an invalid signature returns `address(0)`, which matches an unset
  signer. State keyed on the signature bytes is replayed with the twin.
- **FP:** OpenZeppelin `ECDSA.recover` (rejects high `s` and `address(0)`),
  and no state keyed on signature bytes.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-3/ (#04 direct usage of ecrecover permits malleable signatures); https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-117.md
- **Seed:** inventory: contracts.entry_points (effects signature); grep: `ecrecover\(`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA6. Signed messages replayable across nonces, chains or contracts**

- **D:** An off-chain signature (a relayer authorisation, an operator
  attestation, a permit) covers the action but not a nonce, the chain id,
  the contract address or a deadline. The same signature runs twice, on
  another chain or on another deployment.
- **FP:** EIP-712 domain with chain id and verifying contract, a consumed
  nonce, and an expiry.
- **Source:** https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-121.md
- **Seed:** inventory: contracts.entry_points (effects signature); grep: `nonce|DOMAIN_SEPARATOR|_hashTypedDataV4`
- **PoC:** T-FOUNDRY-REPLAY

**V-SA7. Uninitialised implementation or initializer that anyone calls first**

- **D:** An upgradeable contract's `initialize` is callable by anyone until
  the deployer calls it, or the implementation behind a proxy is left
  uninitialised. An attacker initialises it, becomes owner or sets the
  verifier, and (UUPS) can upgrade or self-destruct the implementation.
- **FP:** The constructor calls `_disableInitializers()`, deployment and
  initialisation happen in one transaction, and `_authorizeUpgrade` is gated.
- **Source:** https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-5vp3-v4hc-gx76
- **Seed:** inventory: contracts.upgrades (initializer, authorize-upgrade); inventory: contracts.entry_points (effects initializer)
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA8. Accounting arithmetic: fee underflow, rounding direction, decimal scaling**

- **D:** Fees are subtracted from an amount without a bound (an `unchecked`
  block, or a circuit that does not bound the fee), amounts round up when
  paid out, or decimals are scaled with a ceiling. The contract pays more
  than it took, or a user drains dust repeatedly.
- **FP:** Every subtraction is bounded (checked arithmetic or a `require`),
  payouts round down, and the circuit and the contract agree on units.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-atomic-settlement/ (#00 transfer amount underflow, #02 decimal ceiling micro-amount theft)
- **Seed:** inventory: contracts.entry_points (effects eth-out or erc20); grep: `unchecked\s*\{|mulDiv|10\s*\*\*`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA9. Stranded funds that anyone can claim**

- **D:** ETH or tokens sent with a call that does not use them (a
  `msg.value` on a non-payable flow kept in a variable, a balance-based
  sweep) stay in the contract, and a permissionless function pays them to
  its caller.
- **FP:** Calls that do not use `msg.value` reject it, and sweeps pay a
  fixed treasury behind a gate.
- **Source:** https://reports.zksecurity.xyz/reports/hinkal-audit/ (#04 attacker can get ETH accidentally sent to the wrapper)
- **Seed:** inventory: contracts.entry_points (payable, effects eth-out); grep: `address\(this\)\.balance|msg\.value`
- **PoC:** T-FOUNDRY-VERIFIER

**V-SA10. Pause switch that also blocks exits or the admin's recovery**

- **D:** `whenNotPaused` guards every state-changing function, including the
  administrative ones that would fix the problem or the withdrawals users
  need, so a pause (or a compromised pauser) freezes funds indefinitely.
- **FP:** Exits and recovery functions are not paused, or a timelocked
  unpause and an escape hatch exist.
- **Source:** https://reports.zksecurity.xyz/reports/renegade-3/ (#02 admin functions are inaccessible if the darkpool is paused)
- **Seed:** grep: `whenNotPaused|_pause\(`; inventory: contracts.privileged_functions (powers pause)
- **PoC:** T-ANALYSIS

**V-SA11. Caller-chosen identifiers that an attacker can take first**

- **D:** A permissionless function records a request, order or note id that
  the caller supplies without binding it to its contents. An attacker who
  sees the id fills or registers it first with dust, and the honest
  operation reverts on "already used".
- **FP:** Ids are derived on-chain from the contents and the sender, or the
  stored record is checked against the full request.
- **Source:** https://reports.zksecurity.xyz/reports/randa-mu-onlyswaps/ (#00 DoS through malicious requestId usage)
- **Seed:** inventory: contracts.entry_points; grep: `(request|order|intent)Id`
- **PoC:** T-FOUNDRY-VERIFIER
