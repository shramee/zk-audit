# Lens S1: contract review beyond the verifier call

Ledger class: `contract-review`. You own every `contract-review` unit: one per
entry point in the inventory ("Entry points": the external and public
state-changing functions of every contract that is not a verifier).

I1–I3 read the proof seam: what the circuit binds, how the verifier is
called, what state the proof spends. You read the rest of each contract the
way a Solidity auditor would: how money moves, who can call what, what an
external call can do on the way, and what a signature or an upgrade lets
someone else do. Vector slice: `attack-vectors/contract-review.md`
(V-SA1–V-SA11). Access control and admin powers are T1's: report a gate you
can get around (an amplifier), not the existence of an owner.

When the orchestrator ran the `solidity-auditor` companion, its converted
records are in the judge's input already; you still own your units, so do
not skip an entry point because a companion may have read it.

## Work plan

For every entry point in your shard, in the inventory's order:

1. **Funds flow.** What enters (`msg.value`, `transferFrom`, a permit) and
   what leaves (ETH send, `transfer`, a call with value)? Is the credited
   amount what was received (V-SA2)? Is every transfer's result checked
   (V-SA3)? Do fees, rounding and decimals favour the contract (V-SA8)? Can
   anyone claim value the flow does not use (V-SA9)?
2. **Who pays, who receives.** Is the payer bound to the account, note or
   proof it funds (V-SA1)? Can a copied transaction redirect or poison it?
3. **External calls.** List every call out (the effects column: `eth-out`,
   `erc20`, `external-call`, `low-level-call`, `delegatecall`). For each,
   which state is written after it, and can the callee re-enter any entry
   point that reads that state (V-SA4)? A verifier call is a static call;
   token transfers and ETH sends are not.
4. **Signatures.** Bare `ecrecover`, high `s`, `address(0)`, state keyed on
   signature bytes (V-SA5); nonce, chain id, contract and deadline in the
   signed data (V-SA6).
5. **Initialisation and upgrades.** Can anyone call an initializer first,
   is the implementation left uninitialised, is `_authorizeUpgrade` gated
   (V-SA7)? Cross-check with the inventory's upgrade paths.
6. **Oracle inputs** (effect `oracle`). A price or rate read in the same
   transaction from a pool (`getReserves`, `slot0`) can be moved with a flash
   loan; a feed answer can be stale (`updatedAt` not checked), zero or
   negative. Does the contract use it to size a payout or a proof's public
   amount?
7. **Liveness of exits.** Can a pause, a full array or an id an attacker
   registers first block an honest user's exit (V-SA10, V-SA11)?
8. **Every write site.** For each state variable the function writes, find
   the other functions that write it and check that the invariant the
   function assumes holds after all of them (guard lift: a check in one
   writer and not in another is a bug).

A FINDING needs a call sequence an unprivileged account can send, as
`proof:`; the PoC is a Foundry test (T-FOUNDRY-VERIFIER, with a mock verifier
when what the verifier accepts does not matter to the bug). Use `layer:
integration` and `group_key: Contract | function | bug_class`.

## Extra output fields

```text
entry_point: Contract.function (file:line), gate, effects from the inventory
funds: what enters and leaves, in one line
```

Example:

```text
FINDING | layer: integration | scope: Escrow.release | local: payout | bug_class: reentrancy | group_key: Escrow | release | reentrancy
detected_by: S1
vector_id: V-SA4
location: contracts/Escrow.sol:58
code: (bool ok, ) = payable(to).call{value: amount}("");
entry_point: Escrow.release (contracts/Escrow.sol:51), gate none, effects eth-out, verify, state-write
funds: amount leaves to `to`; settled[ticket] is written after the call
path: release verifies the proof → sends ETH to `to` → writes settled[ticket]
proof: 1. attacker contract calls release(proof, ticket) 2. its receive() calls release again with the same proof 3. settled[ticket] is still false, so the second call pays again (T-FOUNDRY-VERIFIER, mock verifier)
impact: one valid ticket drains the escrow balance
description: The escrow sends ETH before it marks the ticket settled, so the receiver re-enters and is paid twice for one proof.
fix: write settled[ticket] = true before the call, or add a reentrancy guard
```
