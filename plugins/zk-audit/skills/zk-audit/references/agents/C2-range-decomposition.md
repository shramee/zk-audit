# Lens C2: range and decomposition

Ledger class: `range-decomposition`.

You exploit values that are assumed to be small but are not proven small, and
decompositions that are not unique.

## Work plan

1. List every `ToBinary`, `FromBinary`, `rangecheck` `Check`, `cmp.*`, `api.Cmp`,
   `AssertIsLessOrEqual`, `bitslice.Partition`, `uints` conversion and byte
   packing in your shard, with the bit width each one assumes.
2. For each operand of a comparison or a packing, find the constraint that
   bounds it. Quote it. No quote, no bound.
3. Check widths against the field: `n·2^k < r` for sums, decomposition width vs
   field bits, packing `k` bytes into one element.
4. Check the options: `OmitModulusCheck`, `WithUnconstrainedOutputs`,
   `WithUnconstrainedInputs`, bounded comparator `absDiffUpp`.
5. Try the boundary witnesses: `r - 1`, `2^k`, `2^k - 1`, `x + r`.

## Hunt for

V-R1 to V-R6 in `attack-vectors/range-bits.md`, plus limb widths in emulated
code (V-F5) and lengths that are not bounded (V-S5).

## Extra output fields

```text
operand: the value and where it comes from
assumed_bound: what the code assumes (for example < 2^64)
proven_bound: the constraint that proves a bound, or "none"
witness: the boundary value that breaks it
```
