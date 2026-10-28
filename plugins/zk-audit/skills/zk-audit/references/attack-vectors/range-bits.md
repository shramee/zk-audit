# Attack vectors: range checks and bit decomposition

Slice: `api.ToBinary`, `bits.ToBinary` and its options, `api.Cmp`,
`api.AssertIsLessOrEqual`, `std/math/cmp`, `std/rangecheck`,
`std/math/bitslice`. 6 vectors, V-R1–V-R6.

Mantras: **every comparison operand needs a bit bound first.** **A full-width
decomposition is unique only with the modulus check.**

---

**V-R1. Full-width decomposition accepts `a` and `a + r`**

- **D:** Decomposing a value into as many bits as the field modulus has admits
  two decompositions for small `a`: the bits of `a` and the bits of `a + r`.
  `bits.ToBinary(api, v, bits.OmitModulusCheck())` removes the comparison that
  rules out the alias. Before gnark v0.9.0 the default `api.ToBinary` and
  `api.Cmp` / `IsLess` had no such check, so a prover could prove `a < b` for
  `a > b`. Whenever the bits feed a comparison, a Merkle path, a hash or a bit
  flag, the prover picks the alias.
- **FP:** gnark ≥ v0.9.0 with the default options; a decomposition narrower
  than the modulus (`WithNbDigits(n)` with `n` < field bits, which already
  implies `v < 2^n`); `WithUpperBound(bound)` (gnark ≥ v0.16.4); or
  `OmitModulusCheck` where the doc's condition holds ("the decomposed output is
  manually checked to be unique or if uniqueness is not required").
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg (CVE-2023-44378); `gnark/std/math/bits/conversion.go` (`OmitModulusCheck`, `WithUpperBound`)
- **Seed:** FG-OMIT-MODULUS-CHECK; inventory: stack advisories (gnark < v0.9.0)
- **PoC:** T-ALIAS

**V-R2. Bit or digit outputs left unconstrained by an option**

- **D:** `bits.WithUnconstrainedOutputs()` keeps only the recomposition
  `Σ b_i·2^i == v` and drops the per-bit booleanity constraints.
  `bits.WithUnconstrainedInputs()` drops the booleanity check in `FromBinary`.
  `bitslice.WithUnconstrainedOutputs()` drops the range checks of the two parts.
  A non-boolean "bit" lets the prover satisfy the recomposition with arbitrary
  field elements, and every consumer of the bits computes on garbage.
- **FP:** Each bit is constrained elsewhere on every path: it is an output of
  another decomposition, passes through `AssertIsBoolean`, or the consumer
  (`api.Select`, `api.Lookup2`, `api.Xor`) constrains booleanity itself, per
  `gnark/frontend/api.go`.
- **Source:** `gnark/std/math/bits/conversion.go` (`WithUnconstrainedOutputs`: "This is UNSAFE but is useful when the outputs are already constrained by other circuit constraints"); `gnark/std/math/bitslice/opts.go`
- **Seed:** FG-UNCONSTRAINED-BITS
- **PoC:** T-HINT-OVERRIDE

**V-R3. Comparison of values that can wrap below zero**

- **D:** `api.Cmp`, `api.AssertIsLessOrEqual` and `cmp.IsLess` compare
  canonical representatives in `[0, r)`. A difference computed with `api.Sub`
  that goes negative becomes `r - k`, a huge number. So `api.Cmp(api.Sub(a, b), 0)`
  never returns -1. A check written for integers, such as
  `AssertIsLessOrEqual(api.Sub(in, out), in)`, only rejects `out > in` because
  `r - k` happens to be huge, and it proves nothing once `in` itself is an
  unbounded witness (`in = r - 1` makes almost any `out` pass). Bugs appear when
  the author reasons about integers and the operands were never bounded.
- **FP:** Both operands are bounded to at most `n` bits (below the field size)
  before the comparison, so the integer and field orders agree; or the operands
  come from a decomposition or a byte type (`uints`) with a known width.
- **Source:** `gnark/frontend/api.go` (`Cmp`, `AssertIsLessOrEqual` doc comments); zkSecurity zk-skills circom-auditor V-B1 "Comparator input not range-checked" https://github.com/zksecurity/zk-skills
- **Seed:** FG-CMP-UNBOUNDED
- **PoC:** T-INVALID-ASSIGNMENT

**V-R4. Bounded comparator used outside its precondition**

- **D:** `cmp.NewBoundedComparator(api, absDiffUpp, allowNonDeterministic)` is
  correct only while `|a - b| ≤ absDiffUpp`. Outside that range its doc says a
  proof may fail, or the methods may "wrongly produce reversed results" when
  `|a - b| ≥ P - 2^absDiffUpp.BitLen()`. With `allowNonDeterministicBehaviour`
  set, the system "may have multiple solutions". If the prover controls `a` or
  `b` and nothing bounds their distance, the comparison result is
  prover-chosen.
- **FP:** Range checks on `a` and `b` imply `|a - b| ≤ absDiffUpp` on every
  path, and `allowNonDeterministicBehaviour` is false.
- **Source:** `gnark/std/math/cmp/bounded.go` (`NewBoundedComparator` doc comment)
- **Seed:** grep: `NewBoundedComparator`
- **PoC:** T-INVALID-ASSIGNMENT

**V-R5. Range checker accepts values wider than requested (gnark < v0.9.2)**

- **D:** The lookup-based range checker did not account for a short top
  partition, so `Check(v, n)` accepted values up to 16 bits wider than `n`.
  Field emulation, ECDSA and recursion all depend on it. The advisory rates it
  Low because the extra bits cannot overflow the scalar field, but any
  protocol-level bound enforced with `Check` (amounts, lengths, timestamps) is
  weaker than written.
- **FP:** gnark ≥ v0.9.2, or the bound is also enforced with `bits.ToBinary`.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-rjjm-x32p-m3f7; https://github.com/Consensys/gnark/issues/897
- **Seed:** inventory: stack advisories; grep: `rangecheck.New`
- **PoC:** T-HINT-OVERRIDE

**V-R6. Partition / split with an upper part that is too loosely bounded**

- **D:** Splitting `v` at bit `s` into `lower + 2^s·upper` is sound only if
  `lower < 2^s` and `upper < 2^(n-s)`, and if `n` is below the field size. When
  `upper` is only bounded to the full field width, many `(lower, upper)` pairs
  satisfy the recomposition, including ones that wrap mod r. When the split is
  larger than the decomposition width, the upper part is unconstrained.
- **FP:** gnark ≥ the fix for each case (zkSecurity 01, and the master fix
  "bound split against decomposition width in bitslice.Partition (#1875)"), or
  custom split code that bounds both parts to their exact widths.
- **Source:** zkSecurity gnark-std audit finding 01 ("Partition Function Is Not Sound"), fixed in https://github.com/Consensys/gnark/pull/1165; `gnark/std/math/bitslice/partition.go`
- **Seed:** grep: `bitslice.Partition|Partition\(api`
- **PoC:** T-HINT-OVERRIDE
