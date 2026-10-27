# Attack vectors: control flow, selectors and gated checks

Slice: Go `if` / `switch` / `for` inside circuit code, `api.Select`,
`api.Lookup2`, `std/selector` (`Mux`, `Map`, `BinaryMux`, `Partition`,
`Slice`), flags that switch checks on and off, and `Is*` predicates. 7 vectors,
V-S1–V-S7.

Mantras: **Go code in `Define` runs once, at compile time, on placeholders.**
**A check multiplied by a flag holds trivially when the flag is 0.**

---

**V-S1. Go control flow or Go comparison on a witness value**

- **D:** `frontend.Compile` calls `Define` once, with every witness field set to
  a placeholder variable. A Go `if c.X == 0`, `switch`, `for i < c.N`, or
  `if a == b` on `frontend.Variable`s compares Go interface values at compile
  time. It never sees the prover's assignment. The branch taken at compile time
  is baked into the circuit, and the intended run-time check does not exist.
- **FP:** The condition is a compile-time constant (Go ints, circuit
  parameters, slice lengths), or it is guarded by
  `api.Compiler().ConstantValue(v)`, which is the supported way to specialise
  on constants.
- **Source:** `gnark/frontend/compile.go` (`parseCircuit`: placeholders are set before `Define` runs); `gnark/frontend/api.go` (`ConstantValue`)
- **Seed:** FG-GO-BRANCH-ON-WITNESS
- **PoC:** T-INVALID-ASSIGNMENT

**V-S2. Selector not constrained to its domain**

- **D:** A hand-written multiplexer (`out = s·a + (1 - s)·b`) or a custom
  lookup uses a selector `s` that is never asserted boolean, or in range for
  `n` inputs. With `s = 2` the output is `2a - b`, a value the protocol never
  intended. gnark's PLONK builder once had `Select` without the booleanity
  constraint (fixed). The pattern recurs in user code and in ports of Circom
  muxes.
- **FP:** `api.Select`, `api.Lookup2` and `selector.Mux` constrain their
  selectors (`gnark/frontend/api.go`, `gnark/std/selector/multiplexer.go`: "sel
  needs to be between 0 and n - 1 … otherwise the proof will fail"), or the
  custom selector passes `AssertIsBoolean` / a decomposition first.
- **Source:** Least Authority, Linea zkEVM audit, Issue Q "Missing Binary Constraint in Select Primitive" (`gnark/audits/2024-11 - Least Authority - Linea zkEVM.pdf`); `gnark/std/selector/multiplexer.go`
- **Seed:** FG-SELECTOR; grep: `api\.Mul\(.*api\.Sub\(1,`
- **PoC:** T-INVALID-ASSIGNMENT

**V-S3. A security check gated by a prover-controlled flag**

- **D:** A constraint that should always hold is multiplied by a flag,
  `AssertIsEqual(Mul(enabled, Sub(a, b)), 0)`, or selected away,
  `AssertIsEqual(Select(enabled, a, b), b)`. If `enabled` is a free witness or is
  derived from prover-chosen data, the prover sets it to 0 and the check
  vanishes while the rest of the proof stays valid. Audits of gnark-based
  systems found "activation" constraints missing and leaf-hashing constraints
  that could be "turned off".
- **FP:** The flag is a public input that the contract fixes, a constant, or is
  derived by constraints from data the prover does not control, and the
  disabled branch is independently constrained.
- **Source:** Least Authority, Linea zkEVM audit, Issues H ("Missing Activation Constraint") and M ("Correctness of Leaf Hashing Constraint … Can Be Turned Off"), `gnark/audits/2024-11 - Least Authority - Linea zkEVM.pdf`; zkSecurity zk-skills circom-auditor V-D1 https://github.com/zksecurity/zk-skills
- **Seed:** FG-GATED-ASSERT
- **PoC:** T-INVALID-ASSIGNMENT

**V-S4. Predicate computed but never asserted**

- **D:** `api.IsZero`, `curve.IsOnCurve`, `pairing.IsOnTwist`,
  `verifier.IsValidProof` and `api.Cmp` return a variable. Calling one as a
  statement, or storing the result without asserting it, adds constraints that
  enforce nothing. gnark had this shape in its own G2 membership check: the
  subgroup / twist result was computed and discarded.
- **FP:** The result is asserted (`AssertIsEqual(res, 1)`), multiplied into
  something that is asserted, or exposed as a public output that the verifier
  contract checks.
- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj; `gnark/std/algebra/emulated/sw_bls12381/pairing.go` (`IsOnTwist` vs `AssertIsOnTwist`); zkSecurity zk-skills circom-auditor V-B2 https://github.com/zksecurity/zk-skills
- **Seed:** FG-DISCARDED-PREDICATE
- **PoC:** T-INVALID-ASSIGNMENT

**V-S5. Variable-length data whose length is not bound**

- **D:** Circuits have fixed sizes, so variable-length inputs (messages,
  transaction lists, public-input arrays) are padded to a maximum, and a length
  witness marks the active part. If the length is not range-checked against the
  maximum, not bound to the hashed or committed data, or can wrap (a length of
  `r - 1` passes a `≤ max` check written with wrapped arithmetic), the prover
  chooses which part of the data counts. gnark fixed its own SHA-3 gadget to
  "Bind the Euclidean relation length".
- **FP:** The length is bit-bounded below the maximum, the padding is
  constrained (zero or a fixed pattern) beyond the length, and the length is
  part of what is hashed or exposed.
- **Source:** `gnark/CHANGELOG.md` v0.16.2 ("sha3: Bind the Euclidean relation length"); GHSA-3mvx-pp85-pm65 https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65
- **Seed:** grep: `(?i)(len|length|nb)[A-Z]?\w* +frontend\.Variable`
- **PoC:** T-INVALID-ASSIGNMENT

**V-S6. Flag or selector domain wider than the specification**

- **D:** A value that the specification limits to a small set is constrained
  to a wider set: for example ECRECOVER's `v` constrained to {0, 1, 2, 3}
  (libsecp256k1 semantics) instead of {0, 1} (Ethereum semantics). The circuit
  then accepts inputs the reference implementation rejects, which breaks
  equivalence with the EVM or the spec.
- **FP:** The constraint matches the reference specification exactly, and the
  reference is cited next to it.
- **Source:** Least Authority, Linea zkEVM audit, Issue F "Incomplete Constraint in ECRecover Precompiled Contract" (`gnark/audits/2024-11 - Least Authority - Linea zkEVM.pdf`); https://github.com/Consensys/gnark/blob/master/std/evmprecompiles/01-ecrecover.go
- **Seed:** manual (compare every enum-like witness with its spec)
- **PoC:** T-INVALID-ASSIGNMENT

**V-S7. Special-case branch computes the wrong value**

- **D:** Edge cases are often handled by a separate branch selected in-circuit:
  zero exponent, zero modulus, point at infinity, empty input. When the branch
  condition or its result is wrong, the circuit proves a false value for that
  case. MODEXP returned 1 for `0^0 mod 1`, where the correct result is 0.
- **FP:** Every special case is listed in the spec, tested against a native
  reference implementation, and asserted in-circuit.
- **Source:** Least Authority, Linea zkEVM audit, Issue G "Incorrect Edge Case in ExpMod Precompile Contract" (`gnark/audits/2024-11 - Least Authority - Linea zkEVM.pdf`); https://github.com/Consensys/gnark/blob/master/std/evmprecompiles/05-expmod.go
- **Seed:** manual (diff in-circuit edge cases against the native Go reference)
- **PoC:** T-INVALID-ASSIGNMENT
