# Lens I3: protocol state

Ledger classes: `protocol-state` and `liveness` (one unit each per verifying
or state-writing contract function).

You exploit how the contract and services keep state around proofs: nullifiers,
roots, commitments, nonces and identities.

## Work plan

1. From the inventory's state table, list every nullifier, root, commitment and
   nonce variable with every read and write.
2. Nullifiers: is the nullifier a constrained public input (not proof bytes,
   V-PS1; not signature-derived, V-PS2; bound to context, V-PS4)? Is it checked
   **and** stored in the same call as verification, before any external call
   (reentrancy) and on every path that accepts a proof (batch paths, admin
   paths, alternative entry points)?
3. Roots: is the proof's root checked against a root set or a history window?
   Can an old root be replayed after the tree changes, or can an attacker
   insert a root? Is the window size safe against front-running new deposits?
4. Membership: sentinel leaves (V-PS3), duplicate commitments, leaf insertion
   without checks.
5. Ordering: what state changes happen before the proof is verified? Can a
   failing or reverting path leave state half-updated?
6. Asymmetry: for each pair (deposit / withdraw, insert / spend, single / batch),
   diff the checks on both sides.
7. Liveness (`liveness` units): can an honest, valid proof always be
   accepted in time? Root window size against the insert rate an attacker
   can afford, and who can insert (V-LV4, PoC T-FOUNDRY-STALE-ROOT); verifier
   and batch gas against the block gas limit (V-LV1, V-LV2); payload size
   checks (V-LV3); capacity an attacker can fill (V-LV5); a pause, a
   designated prover or an expiring role that can freeze exits (record the
   party with the T1 fields).

## Extra output fields

```text
state: variable and kind
accepting_paths: every function that accepts a proof and touches it
gap: the path or ordering that breaks the invariant
```
