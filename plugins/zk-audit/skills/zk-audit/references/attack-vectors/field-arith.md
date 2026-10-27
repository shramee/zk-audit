# Attack vectors: field arithmetic (native and emulated)

Slice: `api.Div`, `api.DivUnchecked`, `api.Inverse`, accumulators and sums,
`std/math/emulated` (`Field`, `Element`, `Reduce`, `ReduceStrict`,
`AssertIsInRange`, `Limbs`, custom-modulus operations). 8 vectors, V-F1–V-F8.

Mantras: **field elements wrap.** **An emulated value is width-bounded, not
reduced, unless something reduced it strictly.**

---

**V-F1. `api.DivUnchecked` with a denominator that can be zero**

- **D:** `DivUnchecked(a, b)` constrains `q·b == a`. For `a = b = 0` the output
  `q` is unconstrained in R1CS ("for 0/0 the output is left unconstrained and
  the solver returns 0"). In SCS it is also unconstrained, although the default
  solver fails. A malicious prover sets `q` to any value whenever it can make
  both operands zero.
- **FP:** The denominator is proven non-zero on every path (for example
  `api.AssertIsDifferent(b, 0)`, or `b` is a non-zero constant), or `q` is
  later bound by an independent constraint.
- **Source:** `gnark/frontend/api.go` (`DivUnchecked` doc comment); `gnark/CHANGELOG.md` v0.15.0 "DivUnchecked consistency (#1734)"
- **Seed:** FG-DIV-UNCHECKED
- **PoC:** T-CONSTRAINT-MODEL

**V-F2. `api.Div` / `api.Inverse` on a value that is legitimately zero**

- **D:** `Div(a, b)` and `Inverse(x)` are unsatisfiable when the divisor is
  zero ("If i2 == 0 the constraint will not be satisfied"). If zero is a valid
  protocol input (empty balance, first epoch, point at infinity coordinates),
  honest provers cannot produce a proof. This is a completeness break, and it
  can brick a flow such as a forced withdrawal.
- **FP:** Zero is excluded by the protocol and enforced before the call, or the
  code branches with `api.Select(api.IsZero(b), ...)` on a safe denominator.
- **Source:** `gnark/frontend/api.go` (`Div`, `Inverse` doc comments)
- **Seed:** grep: `api\.(Div|Inverse)\(`
- **PoC:** T-COMPLETENESS

**V-F3. Non-canonical emulated value used where the representation matters**

- **D:** `Field.Reduce` returns a value that fits the modulus width but "may up
  to twice larger than the modulus", so `x` and `x + p` are both valid outputs.
  Operations that read the representation, such as `ToBits`, exponent bits,
  equality of serialized forms, hashing the limbs or comparisons, then give
  different results for the same field value. gnark's own `Exp` was fixed to
  call `ReduceStrict` first because of a "malleability hole for any circuit that
  exponentiates a witness-controlled exponent".
- **FP:** `ReduceStrict`, `ToBitsCanonical`, or `AssertIsInRange` precedes every
  representation-sensitive use.
- **Source:** zkSecurity gnark-std audit finding 08 ("Reduce Function Is Misleading"), https://github.com/Consensys/gnark/issues/1147; `gnark/std/math/emulated/field_reduce.go`; `gnark/std/math/emulated/field_mul.go` (`Exp` comment)
- **Seed:** grep: `\.Reduce\(|\.ToBits\(`; FG-EMULATED-WITNESS
- **PoC:** T-INVALID-ASSIGNMENT

**V-F4. Emulated witness element not checked below the modulus**

- **D:** An `emulated.Element[T]` in the circuit struct is assigned by the
  prover. Its limbs are width-checked on first use, but the value may be
  anywhere below `2^(nbLimbs·nbBits)`, which is above the modulus. If the
  circuit compares it, hashes its limbs, uses it as a scalar, or exposes it as
  a public input, two different limb vectors represent the same field value, or
  a value ≥ p is accepted as an "element".
- **FP:** `f.AssertIsInRange(&c.X)` (or a strict reduction) is applied to
  every witness element whose representation matters.
- **Source:** zkSecurity gnark-std audit finding 0b, `gnark/audits/2024-05 - zksecurity - gnark std.pdf`; `gnark/std/math/emulated/element.go` (`internal` flag, `Initialize`)
- **Seed:** FG-EMULATED-WITNESS
- **PoC:** T-INVALID-ASSIGNMENT

**V-F5. Direct use of `Element.Limbs` bypasses width enforcement**

- **D:** Code that reads `e.Limbs[i]` and does native arithmetic, or builds an
  `Element` from raw limbs (`UnsafeFromLimbs`), skips the conditional width
  check that `Field` methods apply. Limbs from the witness may be arbitrary
  field elements, so a "64-bit limb" can hold any value and sums over limbs
  wrap.
- **FP:** The limbs are produced by a `Field` method in the same circuit (and
  are therefore internal and constrained), or each limb is range-checked before
  native use.
- **Source:** zkSecurity gnark-std audit findings 0b and 04 (`enforceWidthConditional` relies on a non-cryptographic `HashCode`), fixed in https://github.com/Consensys/gnark/pull/1197; `gnark/std/math/emulated/field.go` (`enforceWidthConditional`)
- **Seed:** FG-EMULATED-LIMBS; grep: `UnsafeFromLimbs`
- **PoC:** T-INVALID-ASSIGNMENT

**V-F6. Sum of values or limbs wraps the native field**

- **D:** A sum used as a check, such as "the sum of limbs is zero, so every limb
  is zero", or "the sum of n amounts equals the total", is only sound if the
  sum cannot reach r. With n terms of width k and `n·2^k ≥ r`, or with unbounded
  terms, the prover picks terms that wrap to the target. gnark's emulated
  `IsZero` had a fast path that summed limbs and used an inverted overflow
  condition.
- **FP:** Every term is bounded and `n·2^k < r` holds for the actual widths, or
  each term is checked individually.
- **Source:** zkSecurity gnark-std audit finding 05 (emulated `IsZero` overflow condition), fixed in https://github.com/Consensys/gnark/pull/1145; zkSecurity zk-skills circom-auditor V-C6 "Accumulator sum overflows mod p" https://github.com/zksecurity/zk-skills
- **Seed:** grep: `api\.Add\(.*\.\.\.\)|for .* api\.Add`
- **PoC:** T-INVALID-ASSIGNMENT

**V-F7. A relation that must hold modulo n is checked in the native field**

- **D:** A relation over the scalar field of an emulated curve (or over
  integers) is asserted with native `api` arithmetic, for example
  `s1 + λ·s2 == s + m·n`. Native arithmetic is modulo the native r, so the
  check admits `s + m·n + k·r` for any `k`. The relation holds natively and
  fails over the intended modulus.
- **FP:** The relation is checked with `emulated.Field[n]`, or the operands are
  bounded tightly enough that no multiple of r fits.
- **Source:** zkSecurity gnark-std audit finding 02 (native GLV decomposition checked in the native field), fixed in https://github.com/Consensys/gnark/pull/1167
- **Seed:** manual (look for constants such as a group order used in native `api.Mul` / `api.Add`)
- **PoC:** T-HINT-OVERRIDE

**V-F8. Runtime-modulus operations without a reduced result**

- **D:** `ModMul`, `ModAdd`, `ModExp` and `ModAssertIsEqual` take the modulus as
  an `Element`. If the result or remainder is not proven below that runtime
  modulus, or the modulus itself is a witness that is not validated (non-zero,
  expected width), the prover chooses among several remainders. RSA and
  `ModExp` precompiles are typical users.
- **FP:** The modulus is a constant or a validated public input, and results
  are reduced strictly before use.
- **Source:** GHSA-3mvx-pp85-pm65 ("remainder vs runtime modulus") https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65; `gnark/std/math/emulated/custommod.go`
- **Seed:** grep: `\.Mod(Mul|Add|Exp|AssertIsEqual)\(`
- **PoC:** T-HINT-OVERRIDE
