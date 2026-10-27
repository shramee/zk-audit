# gnark API contracts and footguns

What each API **constrains**, and what the **caller must still do**. Every row
was read in gnark v0.16.4 source (paths relative to the gnark repository). If
the target pins an older version, check `gnark-versions.md` first: several
rows describe fixed behaviour.

`FG-*` ids are the `gnark-inventory` detectors (`gnark-inventory rules` prints
them). A hit means "look here"; it does not mean "bug".

## frontend.API (`frontend/api.go`)

| Call | Constrains | Caller must still |
|---|---|---|
| `Add`, `Sub`, `Mul`, `Neg`, `MulAcc` | the field relation, mod r | bound operands if integer semantics matter; `Sub` below zero is `r - k`. `MulAcc` may mutate its first argument. |
| `Div(a, b)`, `Inverse(x)` | `q·b == a`; unsatisfiable for zero divisor | handle legitimate zeros, or honest provers are bricked (V-F2) |
| `DivUnchecked(a, b)` | `q·b == a` only; **0/0 leaves `q` free** in R1CS (`FG-DIV-UNCHECKED`) | prove `b ≠ 0` or bind `q` elsewhere (V-F1) |
| `ToBinary(v, n...)` | booleanity + recomposition; default full width **with** modulus check since v0.9.0 | pass `n` when a bound is intended; `n` < field bits implies `v < 2^n` |
| `FromBinary(bits...)` | booleanity of each bit | nothing for recomposition; the result is unique only below the modulus |
| `Xor`, `Or`, `And` | booleanity of both inputs | – |
| `Select(b, x, y)` | `b` boolean | check who controls `b` (V-S3) |
| `Lookup2(b0, b1, …)` | `b0`, `b1` boolean | as `Select` (`FG-SELECTOR`) |
| `IsZero(x)` | result ∈ {0,1} and correct | **use the result**; a bare call checks nothing (`FG-DISCARDED-PREDICATE`) |
| `Cmp(a, b)` | -1 / 0 / 1 over canonical values in [0, r) | bound operands; wrapped values compare as huge (`FG-CMP-UNBOUNDED`) |
| `AssertIsLessOrEqual(v, bound)` | `v ≤ bound` over canonical values | same as `Cmp` |
| `AssertIsBoolean`, `AssertIsCrumb`, `AssertIsDifferent`, `AssertIsEqual` | exactly that | – |
| `Println(...)` | nothing | never print secrets: values are resolved by the solver and logged (V-PV5) |
| `Compiler().NewHint(f, n, in...)` | **nothing** about the outputs | bind every output (`FG-HINT-UNREACHED`, `FG-HINT-ESCAPES`, V-H1) |
| `Compiler().ConstantValue(v)` | – (compile time) | use it for compile-time specialisation instead of Go `if` on variables (V-S1) |
| `Compiler().(frontend.Committer).Commit(...)` | a commitment-derived challenge | check gnark version and backend (`FG-COMMIT`, V-CM1/2) |

Compilation (`frontend/compile.go`):

- `Define` must have a pointer receiver. It runs **once** at compile time with
  placeholder variables, so Go control flow on variables is a compile-time
  decision (`FG-GO-BRANCH-ON-WITNESS`).
- Fields tagged `gnark:"-"` are not witness inputs (`FG-SKIP-TAG`).
- `frontend.IgnoreUnconstrainedInputs()` allows inputs that no constraint uses:
  "should not be used in production settings" (`FG-IGNORE-UNCONSTRAINED-INPUTS`).

Witness layout (`frontend/schema/walk.go`, `frontend/schema/tags.go`):

- Order is the struct walk: fields in declaration order, nested structs
  depth-first, arrays and slices element by element. Public leaves form the
  public witness in that order, and the contract input array must match it.
- Tags: `gnark:"name,public"`, `gnark:",secret"`, `gnark:",inherit"`,
  `gnark:"-"`. Secret wins if both options are given. A child inherits its
  parent's visibility, and a child that contradicts a set parent is a compile
  error.
- **Embedded fields are walked inline and their tag is ignored**: an embedded
  struct tagged `gnark:",public"` still contributes secret leaves.
- Empty slices are skipped with a warning. Nil pointers contribute nothing.
  Unexported leaf fields fail compilation ("can't set val").

## std/math/bits (`std/math/bits/conversion.go`)

| Option / call | Effect | Caller must still |
|---|---|---|
| `WithNbDigits(n)` | output length `n`; smaller than the value's width makes the circuit unsatisfiable | – |
| `OmitModulusCheck()` | drops the `< r` comparison at full width: **`a` and `a + r` both decompose** | prove uniqueness yourself (`FG-OMIT-MODULUS-CHECK`, V-R1) |
| `WithUnconstrainedOutputs()` | drops per-digit constraints, keeps the sum | constrain every digit elsewhere (`FG-UNCONSTRAINED-BITS`, V-R2) |
| `WithUnconstrainedInputs()` | `FromBinary` skips booleanity of inputs | same |
| `WithUpperBound(b)` (v0.16.4+) | compares against `b` instead of `r - 1` | – |
| `ToNAF` | digits in {-1, 0, 1} + sum; adjacency enforced only after the zkSecurity 09 fix | check version (V-H4) |

## std/math/cmp and std/rangecheck

- `cmp.IsLess`, `cmp.IsLessOrEqual` (`std/math/cmp/generic.go`): full
  decompositions, correct over canonical values.
- `cmp.NewBoundedComparator(api, absDiffUpp, allowNonDet)`
  (`std/math/cmp/bounded.go`): correct **only while `|a - b| ≤ absDiffUpp`**.
  Outside the bound results may be reversed, or non-deterministic when
  `allowNonDet` is true (V-R4).
- `rangecheck.New(api).Check(v, n)` (`std/rangecheck/rangecheck.go`): uses
  native range checks, a commitment-based log-derivative argument when the
  builder is a `frontend.Committer` (so the Groth16 commitment advisories
  apply), or bit decomposition. Before v0.9.2 it accepted up to 16 extra bits
  (V-R5).

## std/math/emulated (`std/math/emulated/`)

| API | Constrains | Caller must still |
|---|---|---|
| witness `Element[T]` fields | limbs width-checked **on first use** (`enforceWidthConditional`) | prove `< p` with `AssertIsInRange` where canonicity matters (`FG-EMULATED-WITNESS`, V-F4) |
| `ValueOf[T](v)` | witness assignment only | use `Field.NewElement` for in-circuit constants (`FG-EMULATED-VALUEOF-IN-CIRCUIT`) |
| `Reduce(a)` | width of the modulus; **value may be ≥ p** | `ReduceStrict` / `ToBitsCanonical` for representation-sensitive use (V-F3) |
| `ToBits(a)` | bits of the raw limb value | `ToBitsCanonical` for canonical bits |
| `IsZero(a)` | flag that accepts both representations of zero (0 and p) after `Reduce` | use the result |
| `e.Limbs`, `UnsafeFromLimbs` | nothing | range-check limbs before native use (`FG-EMULATED-LIMBS`, V-F5) |
| `NewHint*` | nothing | bind outputs as for native hints |
| `ModMul`, `ModAdd`, `ModExp`, `ModAssertIsEqual` (runtime modulus) | the relation modulo the given modulus | validate the modulus; reduce results (V-F8) |

## std/math/uints (`std/math/uints/`)

- `BinaryField.ValueOf(x)` decomposes `x` into range-checked bytes and, after
  the zkSecurity 03 fix, recomposes them. Check the version (V-H1).
- `U8.Val`: "NB! dont't access it directly!" (`std/math/uints/bytes.go`).

## std/selector (`std/selector/`)

- `Mux(api, sel, inputs...)`: `sel` must be in `[0, n-1]` "otherwise the proof
  will fail".
- `Map(api, key, keys, values)`: missing key, no proof; **duplicate keys, the
  output may be any linear combination** of the matching values (V-G3).
- `BinaryMux(api, selBits, inputs)`: asserts each selector bit boolean.
- `Partition`, `Slice`: positions are witness-dependent; check the bounds the
  caller assumes.

## std/accumulator/merkle (`std/accumulator/merkle/verify.go`)

- `MerkleProof{RootHash, Path}` and `VerifyProof(api, h, index)`: the leaf is
  `Path[0]`; leaf and node hashing have **no domain separation**; the index is
  decomposed into `depth` bits. The caller binds `Path[0]` to a preimage and
  `RootHash` to the contract's root (`FG-MERKLE`, V-M2 to V-M5).

## std/hash

- `mimc.NewMiMC(api)` (`std/hash/mimc/mimc.go`): Miyaguchi-Preneel; length
  extension; no domain tag (`FG-MIMC`, V-M1).
- Hashers are stateful: `Sum()` flushes the buffered input but keeps the chaining
  state (`std/internal/mimc/mimc.go`). Call `Reset()` between independent
  uses, or the next digest depends on the previous one.

## std/signature

- `eddsa.Verify(curve, sig, msg, pk, h)` (`std/signature/eddsa/eddsa.go`):
  asserts `S < order` (v0.14.0+), `A` and `R` on the curve, `A` not of small
  order. **Mixed-order keys are accepted** (V-E2). `IsValid` returns a flag
  instead.
- `ecdsa` `PublicKey.Verify` (`std/signature/ecdsa/ecdsa.go`): "We assume that
  the message msg is already hashed to the scalar field" (V-E3).

## std/recursion/groth16 (`std/recursion/groth16/verifier.go`, `opts.go`)

| API | Note |
|---|---|
| `ValueOfVerifyingKey` | the VK is a witness: bind it (`FG-VK-AS-WITNESS`, V-CM4) |
| `ValueOfVerifyingKeyFixed` | for VKs embedded as constants (`gnark:"-"`); on a witness VK the precomputed lines are **not constrained** |
| `AssertProof(vk, proof, w)` | bind the inner public inputs `w` to the outer statement (V-CM5) |
| `IsValidProof` | returns a flag; assert it (V-CM6) |
| `SwitchVerificationKey(idx, vks)` | `vks` should be a constant list |
| `WithSubgroupCheck()` | subgroup checks on proof points run only with this option |
| `WithCompleteArithmetic()` | deprecated no-op: complete arithmetic is the default |

## Backends and export

- `groth16.Setup(ccs)` (`backend/groth16/groth16.go`): single-party setup;
  production keys need an MPC ceremony (`backend/groth16/bn254/mpcsetup`)
  (`FG-DEV-SETUP`, V-PV1).
- `test/unsafekzg.NewSRS`: "for test purposes only" (`FG-DEV-SETUP`).
- `VerifyingKey.ReadFrom` checks points; `UnsafeReadFrom` "will not check that
  decode points are on the curve and in the correct subgroup"
  (`backend/groth16/bn254/marshal.go`, `FG-UNTRUSTED-DESERIALIZE`, V-PV2).
- `vk.ExportSolidity(w, opts...)` embeds the VK. Groth16 `verifyProof(bytes,
  uint256[N])` **reverts** on failure and rejects inputs ≥ r. PLONK
  `Verify(bytes, uint256[])` **returns a bool** (V-VC3).
- Commitments with Solidity: prove with
  `solidity.WithProverTargetSolidityVerifier(backend.GROTH16)`; keep
  `WithHashToFieldFunction` identical everywhere (`backend/solidity/solidity.go`,
  `FG-HASH-TO-FIELD`, V-VC4).

## Testing (`test/`)

- `test.IsSolved` and `assert.ProverSucceeded` run the **honest** hints. A green
  test suite says nothing about under-constraint.
- Override hints with `solver.OverrideHint(solver.GetHintID(h), evil)`, passed
  through `test.WithSolverOpts(...)` (with `test.NoTestEngine()`) or
  `backend.WithSolverOptions(...)` to `groth16.Prove`. On v0.15+ the test engine
  also takes `test.WithReplacementHint(id, evil)`. See `poc-templates.md`.
