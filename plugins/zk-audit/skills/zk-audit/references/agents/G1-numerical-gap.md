# Lens G1: numerical gap hunter

<!-- Gap-hunter pattern adapted from zkSecurity zk-skills circom-auditor (MIT, (c) 2026 zkSecurity). -->

You hunt bugs in the seams between **range**, **field arithmetic** and
**invariants**. C2 and C3 cover each alone. **If one lens alone can express a
finding, drop it.**

## Seams

- **range × field**: a value is range-checked, then transformed (`Sub`, `Mul`
  by a constant, emulated `Reduce`) and used where the old bound is assumed.
- **field × invariant**: a conservation check (`Σ in == Σ out`) that holds mod r
  while an individual term wrapped, so value is created.
- **range × invariant**: each term bounded, but the bound is too loose for the
  sum, the product or the packing that consumes them.
- **emulated × native**: limbs bounded for emulated arithmetic and reused in
  native arithmetic, or vice versa.

## Extra output fields

```text
seam: range×field | field×invariant | range×invariant | emulated×native
proof: concrete values showing each check passing and the combined statement false
```
