# Lens L1: doc contract vs enforced constraints

Ledger class: `doc-contract`. You own one unit per exported gadget
(`gadget:<package>.<Func>|doc-contract`).

A gadget library has no circuit of its own: its users trust the doc comment.
You compare what each exported gadget **promises** with what its constraints
**enforce**, and what it **requires** of the caller with what it **says** it
requires. A promise the constraints do not enforce is a soundness bug in
every circuit that relies on it. A requirement the doc does not state is a
bug waiting in the caller.

## Inputs

- The `Exported gadgets` section of `inventory.md` and the gadget lines in
  section 3 of your bundle: signature, doc comment, input flows, output
  sources, constraining calls (including same-package callees), hint sites
  and `doc checks`.
- `doc checks` are facts from a syntactic pass, not verdicts. "no range
  constraint appears" can be wrong when the constraint lives in another
  package or behind an interface; a check that is absent proves nothing.

## Work plan

For each gadget, in inventory order:

1. **Promise table.** Write each promised property in one line: output
   boolean, output in `[0, 2^n)`, output canonical (`< p`, unique
   encoding), point on the curve or in the subgroup, result non-zero,
   relation between outputs and inputs (`a = q*b + r`, recomposition),
   "asserts X" (the gadget fails for every input that violates X). An
   undocumented gadget promises what its name says (`Decompose`, `Less`,
   `Reduced`); say that you took the contract from the name.
2. **Enforcement.** For each promise, name the constraint lines that
   enforce it, reading the body and every helper it calls, std gadgets
   included (at the pinned version, from the absolute std path in your
   bundle). "Reached" for a hint output only means it appears in some
   constraint: write the set of values the constraints allow.
3. **Gap.** A promise with a larger allowed set is a candidate. Build the
   witness: the input, the hint outputs or assignment a prover picks, and
   the false property they satisfy (`r = b + 1`, a bit equal to 3, an
   element equal to `p + 5`).
4. **Preconditions.** List what the gadget silently needs from its inputs
   (range, boolean, non-zero, canonical, on-curve, distinct, a maximum
   length, a selector domain). Compare with the documented preconditions
   (`doc_preconditions`). An unstated precondition that an honest caller
   can violate, with a wrong but accepted result, is a candidate; state the
   input that shows it.
5. **Completeness.** A promise the constraints over-enforce (an honest
   input in the documented domain that cannot be proven: zero, `p - 1`,
   maximum width, point at infinity) is a completeness finding.
6. **Native reference.** Name the native function that computes the same
   value (the library's own Go code, `gnark-crypto`, `math/big`), or say
   there is none. Phase 4 uses it for the differential test.

## Hunt for

- "returns the bits" with no `AssertIsBoolean` (recomposition alone accepts
  non-boolean limbs);
- quotient / remainder gadgets without `r < divisor`;
- "canonical" or "reduced" results from a non-strict reduction
  (`Reduce` instead of `ReduceStrict` in `std/math/emulated`);
- comparisons that assume bounded inputs without saying so;
- selectors and lookups that accept indices outside the documented domain;
- `Is*` gadgets that return a value the caller must also assert;
- outputs returned straight from a hint (`result-from-hint` checks): the
  doc must say what the caller has to constrain;
- methods that store an unchecked value in the gadget object and use it in a
  later method (`escapes` into a field);
- options (`WithNbDigits`, `OmitModulusCheck`, unchecked variants) that
  weaken a promise without the doc saying so.

## Extra output fields

```text
gadget: <package>.<Func> (inventory id)
promise: the doc sentence, or "from the name"
enforced: the constraint lines, or "none"
allowed: the set of values the constraints allow for the promised output
native: the reference function for the differential test, or "none"
```

Use T-INVALID-ASSIGNMENT or T-HINT-OVERRIDE through the per-gadget harness
(`gnark-inventory harness`) for the PoC; never write a finding whose witness
you cannot state.
