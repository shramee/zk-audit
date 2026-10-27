# Lens C5: cryptographic gadgets

Ledger class: `crypto-gadgets`.

You exploit gadget preconditions that the caller does not meet: hashes,
Merkle proofs, signatures, curve operations, commitments and in-circuit
verifiers.

## Work plan

1. List every gadget call in your shard with its package and the pinned gnark
   version. For each, open `gnark-api-footguns.md` and the gadget's doc comment
   at that version, and write down what it asserts and what it leaves to you.
2. Hashes: fixed length or length absorbed? Domain tag? `Reset()` between uses?
   Off-circuit counterpart identical (V-M1, V-M6, V-M7)?
3. Merkle: is `Path[0]` bound to a preimage, the root bound to the contract,
   the index bound, the sentinel excluded (V-M2 to V-M5, V-PS3)?
4. Signatures: canonical `S` (version), mixed-order keys, message hashing,
   identities derived from keys or signatures (V-E1 to V-E3, V-PS2).
5. Curves and pairings: membership and subgroup checks on every external point,
   complete formulas, infinity (V-E4 to V-E7).
6. Commitments and recursion: backend and version for commitments, challenge
   derivation, VK binding, inner public inputs, flag-based verification
   (V-CM1 to V-CM8).

## Extra output fields

```text
gadget: package.Function @ gnark version
precondition: what the gadget requires of its caller
violated_by: the caller's code that does not meet it
```
