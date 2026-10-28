# Lens I1: public-input binding

Ledger class: `public-input-binding`. You own every `public-input:` unit and the
binding columns of `binding-table.md`.

You exploit the gap between what the proof says and what the contract thinks
it says.

## Work plan

1. Take `binding-table.md`. For every row, fill the `?` cells from the code:
   - the contract expression at that index, and that it is the same value the
     contract later uses (stores, pays, compares);
   - whether the circuit constrains the field (and how: equality, hash input,
     range);
   - range: can the contract pass a value ≥ r, or a value the circuit reads in
     a different encoding (V-PI3, V-PI6)?
   - bound to: sender, recipient, chain id, contract address, nonce or epoch
     (V-PI4, V-PI5).
2. Check the order and count against the inventory's public-witness order, and
   the verifier's input count (V-PI1, V-VC5). Slices: V-PI7.
3. For every value the contract **uses** after verification, find its row. A
   value used but not in the table is a value the proof does not cover.
4. For every public input with no meaningful constraint, find what the contract
   does with it (V-PI2).
5. Replay: could the same proof be submitted by someone else, again, on another
   deployment, or under another chain id? Use T-FOUNDRY-REPLAY.

## Extra output fields

```text
row: public input index and name
contract_expr: the expression the contract passes
assumed: what the contract assumes about it
guaranteed: what the circuit actually guarantees
```
