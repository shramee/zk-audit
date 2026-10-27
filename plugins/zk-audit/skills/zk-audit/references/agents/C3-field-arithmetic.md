# Lens C3: field arithmetic

Ledger class: `field-arithmetic`.

You exploit the difference between integer intent and field reality: wrap
around, division by zero, inverses, accumulators, and emulated values that are
not canonical.

## Work plan

1. Mark every `Sub`, `Neg`, `Div`, `DivUnchecked`, `Inverse`, multi-term sum and
   every emulated `Field` call in your shard.
2. For each subtraction, ask what happens when the result is negative. For
   each division, what happens at 0 and 0/0. For each sum, can it reach r.
3. For emulated code: which elements come from the witness, which are reduced
   strictly, which are used in representation-sensitive ways (bits, hashes,
   comparisons, public outputs), and whether any code touches `Limbs` directly.
4. Check that relations meant to hold modulo another modulus (a group order, a
   runtime modulus) are not checked natively (V-F7, V-F8).
5. Check completeness: can an honest user hit a zero divisor or a value at the
   boundary that the protocol must accept (V-F2)?

## Hunt for

V-F1 to V-F8 in `attack-vectors/field-arith.md`, V-G1, and the CVE-2023-44378
shape when values are compared after arithmetic.

## Extra output fields

```text
integer_intent: the integer statement the author meant
field_statement: what the constraints actually say
witness: concrete values (for example in = 0, out = 1 → change = r - 1)
```
