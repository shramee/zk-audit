# lib-gadgets answer key

A gnark v0.14.0 gadget library with no production circuit and no verifier
contract: the library-mode fixture. Doc comments state each gadget's
contract; four of them do not hold. PoCs: `pocs/poc_test.go` (through the
wrappers `gnark-inventory harness` generates, copied unchanged), run by
`make eval-pocs`.

| Id | File | Gadget | Bug | Expected |
|---|---|---|---|---|
| L1 | `gadgets/bits.go` | `ToBits` | The doc promises boolean bits; only the recomposition is enforced (via the unexported `recompose`). For v = 1, nbBits = 2 the "bits" (3, r - 1) are accepted (`TestPoC_ToBitsNotBoolean`, T-HINT-OVERRIDE). | confirmed, high or critical |
| L2 | `gadgets/arith.go` | `DivMod` | The doc promises 0 <= r < b; only a = q*b + r is enforced, so (q - 1, r + b) is accepted (`TestPoC_DivModRemainderNotBounded`). | confirmed, medium to critical |
| L3 | `gadgets/field.go` | `Canonical` | The doc promises a result below p; `Reduce` leaves an element without overflow as is, so Canonical(p + 5) is p + 5 limb for limb (`TestPoC_CanonicalNotReduced`; `ReduceStrict` is the control). | confirmed, low to high |
| L4 | `gadgets/bits.go` | `Mux3` | Documents sel in {0, 1, 2}; sel = 3 passes the two-bit decomposition and returns in[2]. No precondition is stated (`TestPoC_Mux3SelectorThree`). | any verdict, low or info |

Decoys (must not be confirmed): `IsLess` is correct under its documented
64-bit precondition (differential test against `IsLessNative`,
`TestDecoy_IsLessDifferential`); `AssertRange` (`bits.ToBinary`) is sound
(`TestDecoy_AssertRangeBounds`); `Accumulator.Add` documents that the caller
must pass a boolean. Not scored: the gnark and gnark-crypto advisories of
`go.mod` (Phase 0) and `DivMod` with b = 0 (documented precondition).

Inventory expectations (`internal/inventory/gadgets_test.go`): nine
gadgets; doc checks `promise-boolean` and `promise-range` on `ToBits`,
`promise-range` on `DivMod`, `promise-range` and `promise-canonical` on
`Canonical`, none on the controls.
