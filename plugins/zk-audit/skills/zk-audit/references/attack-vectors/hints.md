# Attack vectors: hints

Slice: hint call sites (`api.Compiler().NewHint`, `api.NewHint`, emulated
`Field.NewHint*`) and the gadgets built on them. 7 vectors, V-H1–V-H7.

Mantras: **a hint output is a free variable until a constraint pins it.**
**`test.IsSolved` and `assert.ProverSucceeded` run the honest hint, so they can
never show an under-constrained hint.**

---

**V-H1. Hint output used without any binding constraint**

- **D:** A `NewHint` output flows into arithmetic, a selector, a hash or a public
  output, but no `Assert*`, range check or recomposition ties it back to its
  inputs. The prover returns any value for it. gnark's own std had this shape
  repeatedly. Byte values from a `toBytes` hint were range-checked to 8 bits
  but never recomposed into the input, so `uints.ValueOf(x)` could return the
  bytes of any value.
- **FP:** The output is recomposed and asserted equal to the input
  (`AssertIsEqual(ToValue(bytes), x)`) or is otherwise uniquely determined by an
  equality, and every part is range-checked to the width the recomposition
  assumes.
- **Source:** zkSecurity gnark-std audit finding 03, fixed in https://github.com/Consensys/gnark/pull/1139 (report: https://reports.zksecurity.xyz/reports/consensys-gnark-std/); https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65
- **Seed:** FG-HINT-UNREACHED, FG-HINT-ESCAPES
- **PoC:** T-HINT-OVERRIDE, then T-PROVE-VERIFY

**V-H2. Recomposition holds but limbs or carries are not range-checked**

- **D:** The hint returns limbs, carries or padding. The code asserts the
  linear recomposition, for example `Σ limb_i·2^(k·i) == x`, but some limb has
  no `k`-bit bound. With an unbounded limb the recomposition has many solutions:
  shift a multiple of `2^k` from one limb to the next, or let a limb underflow
  mod r. For emulated subtraction, the padding `pad` must satisfy
  `pad[i] ≥ b[i]` per limb; a hint-supplied pad without that constraint makes
  `a - b` underflow per limb.
- **FP:** Every limb and carry is checked with `rangecheck.New(api).Check(limb, k)`
  or a `bits.ToBinary(..., WithNbDigits(k))` whose width matches the
  recomposition, and the top limb's bound keeps the sum below r.
- **Source:** zkSecurity gnark-std audit finding 07 (`modSub` padding), fixed in https://github.com/Consensys/gnark/pull/1200; GHSA-3mvx-pp85-pm65 ("emulated carry not range-checked") https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65
- **Seed:** inventory: hints[].outputs[].reached_by lacks a Check / ToBinary for an output used in a recomposition; grep: `NewHint` near `Add(.*Mul(.*Lsh`
- **PoC:** T-HINT-OVERRIDE

**V-H3. Quotient / remainder hint without `remainder < divisor`**

- **D:** Integer division or modular reduction is computed by a hint
  `(q, r) = hint(a, b)` and checked only with `q·b + r == a`. Without
  `r < b` (or `r < modulus` for a runtime modulus), the prover picks `q' = q - 1`
  and `r' = r + b`, so the circuit proves a wrong quotient. A range check
  `r < 2^k` is not enough when `b < 2^k`.
- **FP:** `r` is checked against the actual divisor, for example with a bounded
  comparison `AssertIsLess(r, b)` whose operands are themselves bit-bounded, or
  with `ModReduce` / `ReduceStrict` for emulated values. `q` is also bounded so
  that `q·b + r` cannot wrap r.
- **Source:** GHSA-3mvx-pp85-pm65 ("remainder vs runtime modulus") https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65; `gnark/CHANGELOG.md` v0.16.2 "Bind quotient in smallCheckZero" and v0.16.3 "range check quotient for small fields"
- **Seed:** FG-HINT-UNREACHED; grep: `NewHint\(.*(div|quo|rem|mod)`
- **PoC:** T-HINT-OVERRIDE

**V-H4. Hint returns a representation that is valid but not unique**

- **D:** A canonical form (NAF, signed digits, windowed decomposition) is
  produced by a hint. The circuit checks digit ranges and the weighted sum, but
  not the canonicity rule, for example "no two adjacent non-zero NAF digits".
  The prover then supplies a different valid-looking representation. Any later
  logic that relies on the canonical form computes on prover-chosen data.
- **FP:** The circuit enforces the canonicity rule, or the consumer is correct
  for every representation with the same value.
- **Source:** zkSecurity gnark-std audit finding 09 (`ToNAF` missing adjacency constraint), fixed in https://github.com/Consensys/gnark/pull/1164
- **Seed:** grep: `ToNAF|NewHint\(.*(naf|digits|window)`
- **PoC:** T-HINT-OVERRIDE

**V-H5. Hint-supplied curve point or scalar-multiplication result not checked on the curve**

- **D:** An optimisation such as fake-GLV gets `[s]P` or a decomposition from a
  hint and checks an algebraic relation that holds for points off the curve, or
  for a wrong combination of sub-results. The prover supplies a point that is
  not on the curve, and the relation still holds. Downstream signature checks
  (ECDSA, P-256) then accept forgeries.
- **FP:** Every hint-supplied point is passed to `AssertIsOnCurve` (or the
  gadget's subgroup check) before it is used, and the scalar relation is checked
  modulo the scalar field order.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-7fx8-hmgc-82jp; `gnark/std/algebra/emulated/sw_emulated/point.go` (`AssertIsOnCurve`)
- **Seed:** inventory: stack advisories; grep: `NewHint.*(Point|ScalarMul|glv)`
- **PoC:** T-HINT-OVERRIDE

**V-H6. GLV sub-scalars from a hint not bounded, or decomposition checked in the wrong field**

- **D:** Scalar multiplication splits `s` into `s1 + λ·s2` with a hint. If
  `s1, s2` are not range-bounded, or the relation `s1 + λ·s2 == s mod n` is
  checked in the native field instead of modulo the group order `n`, the
  decomposition has extra solutions and `[s]P` can be replaced by `[s']P`.
- **FP:** `s1` and `s2` are bounded to the lattice bound, and the relation is
  checked modulo `n` with emulated arithmetic (or with a proof that no native
  wraparound is possible for the bounded values).
- **Source:** zkSecurity gnark-std audit finding 02, fixed in https://github.com/Consensys/gnark/pull/1167; `gnark/CHANGELOG.md` v0.16.0 "GLV subscalar range checks (#1778)"; GHSA-3mvx-pp85-pm65 https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65
- **Seed:** grep: `NewHint.*(glv|GLV|decompose)`; inventory: stack advisories
- **PoC:** T-HINT-OVERRIDE

**V-H7. Helper returns hint outputs and every caller assumes the helper constrained them**

- **D:** A helper computes values with a hint and returns them (or stores them
  in a struct) without constraints, documenting or implying that the result is
  safe. Callers treat the result as constrained. This is the leaky-abstraction
  pattern: correctness depends on every consumer remembering to add the check.
  In gnark's emulated package, the documented duty was to call the width check
  on every non-internal `Element`.
- **FP:** Every call site of the helper adds the binding constraint, or the
  helper's doc comment states the caller's duty and every caller is shown to
  meet it.
- **Source:** zkSecurity gnark-std audit finding 0b ("Field API Is A Leaky Abstraction"), `gnark/audits/2024-05 - zksecurity - gnark std.pdf`; https://reports.zksecurity.xyz/reports/consensys-gnark-std/
- **Seed:** FG-HINT-ESCAPES
- **PoC:** T-HINT-OVERRIDE
