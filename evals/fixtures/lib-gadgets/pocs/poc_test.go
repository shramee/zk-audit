package gadgets

// Eval PoCs for the lib-gadgets fixture. They use the wrappers that
// `gnark-inventory harness` generated (zkaudit_harness_*_test.go, copied
// unchanged), the way a library-mode audit does: T-HINT-OVERRIDE and
// T-INVALID-ASSIGNMENT through the wrapper, and differential tests against
// the library's native reference functions.

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// solveOverride compiles c, builds the witness of a and solves it, with
// the hint h replaced by evil when evil is not nil.
func solveOverride(t *testing.T, c, a frontend.Circuit, h solver.Hint, evil solver.Hint) error {
	t.Helper()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(a, field)
	if err != nil {
		t.Fatal(err)
	}
	if evil == nil {
		_, err = ccs.Solve(w)
	} else {
		_, err = ccs.Solve(w, solver.OverrideHint(solver.GetHintID(h), evil))
	}
	return err
}

// L1: ToBits promises boolean bits; only the recomposition is enforced, so
// the "bits" (3, r - 1) decompose v = 1 with nbBits = 2.
func TestPoC_ToBitsNotBoolean(t *testing.T) {
	shape := func() *wrapToBits {
		c := newWrapToBits()
		c.NbBits, c.Out0 = 2, make([]frontend.Variable, 2)
		return c
	}
	rMinus1 := new(big.Int).Sub(field, big.NewInt(1))
	bad := shape()
	bad.V, bad.Out0[0], bad.Out0[1] = 1, 3, rMinus1
	evil := func(_ *big.Int, in, out []*big.Int) error {
		out[0].SetInt64(3)
		out[1].Set(rMinus1)
		return nil
	}
	if err := solveOverride(t, shape(), bad, bitsHint, evil); err != nil {
		t.Fatalf("attack: the non-boolean decomposition should be accepted: %v", err)
	}
	if err := solveOverride(t, shape(), bad, bitsHint, nil); err == nil {
		t.Fatal("control: the honest hint must reject the false statement")
	}
	good := shape()
	good.V, good.Out0[0], good.Out0[1] = 1, 1, 0
	if err := solveOverride(t, shape(), good, bitsHint, nil); err != nil {
		t.Fatalf("sanity: the honest decomposition must be accepted: %v", err)
	}
}

// L1: DivMod promises 0 <= r < b; only a = q*b + r is enforced, so
// (q - 1, r + b) is accepted for a = 17, b = 5.
func TestPoC_DivModRemainderNotBounded(t *testing.T) {
	bad := &wrapDivMod{A: 17, B: 5, Out0: 2, Out1: 7}
	evil := func(_ *big.Int, in, out []*big.Int) error {
		out[0].SetInt64(2)
		out[1].SetInt64(7)
		return nil
	}
	if err := solveOverride(t, newWrapDivMod(), bad, divModHint, evil); err != nil {
		t.Fatalf("attack: r = 7 >= b = 5 should be accepted: %v", err)
	}
	if err := solveOverride(t, newWrapDivMod(), bad, divModHint, nil); err == nil {
		t.Fatal("control: the honest hint must reject r = 7")
	}
	if err := solveOverride(t, newWrapDivMod(), &wrapDivMod{A: 17, B: 5, Out0: 3, Out1: 2}, divModHint, nil); err != nil {
		t.Fatalf("sanity: %v", err)
	}
}

// limbsOf splits v into the four 64-bit limbs of an emulated BN254 base
// field element, without reducing it.
func limbsOf(v *big.Int) []frontend.Variable {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	out := make([]frontend.Variable, 4)
	for i := range out {
		out[i] = new(big.Int).And(new(big.Int).Rsh(v, uint(64*i)), mask)
	}
	return out
}

// canonicalLimbs is the harness of Canonical with the limb-by-limb output
// check the generated wrapper's comment asks for (a canonical promise is
// about the representation, f.AssertIsEqual compares modulo p). Strict
// switches the gadget to ReduceStrict: the control.
type canonicalLimbs struct {
	X      emulated.Element[emparams.BN254Fp]
	Out    [4]frontend.Variable
	Strict bool `gnark:"-"`
}

func (c *canonicalLimbs) Define(api frontend.API) error {
	f, err := emulated.NewField[emparams.BN254Fp](api)
	if err != nil {
		return err
	}
	out := Canonical(f, &c.X)
	if c.Strict {
		out = f.ReduceStrict(&c.X)
	}
	for i := range c.Out {
		api.AssertIsEqual(out.Limbs[i], c.Out[i])
	}
	return nil
}

// L1: Canonical promises a result below p; Reduce returns x = p + 5 as is.
func TestPoC_CanonicalNotReduced(t *testing.T) {
	p := emparams.BN254Fp{}.Modulus()
	x := new(big.Int).Add(p, big.NewInt(5))
	assign := func(v, out *big.Int) *canonicalLimbs {
		a := &canonicalLimbs{X: emulated.Element[emparams.BN254Fp]{Limbs: limbsOf(v)}}
		copy(a.Out[:], limbsOf(out))
		return a
	}
	if err := test.IsSolved(&canonicalLimbs{}, assign(x, x), field); err != nil {
		t.Fatalf("attack: Canonical(p + 5) should return p + 5, not 5: %v", err)
	}
	if err := test.IsSolved(&canonicalLimbs{Strict: true}, assign(x, x), field); err == nil {
		t.Fatal("control: ReduceStrict must reject p + 5 as its result")
	}
	if err := test.IsSolved(&canonicalLimbs{Strict: true}, assign(x, big.NewInt(5)), field); err != nil {
		t.Fatalf("sanity: ReduceStrict(p + 5) = 5: %v", err)
	}
}

// L1 (undocumented precondition): Mux3 documents sel in {0, 1, 2}, but
// sel = 3 is accepted and returns in[2].
func TestPoC_Mux3SelectorThree(t *testing.T) {
	in := [3]frontend.Variable{10, 20, 30}
	if err := test.IsSolved(newWrapMux3(), &wrapMux3{Sel: 3, In: in, Out0: 30}, field); err != nil {
		t.Fatalf("attack: sel = 3 should be accepted: %v", err)
	}
	if err := test.IsSolved(newWrapMux3(), &wrapMux3{Sel: 4, In: in, Out0: 30}, field); err == nil {
		t.Fatal("control: sel = 4 does not fit two bits and must be rejected")
	}
	if err := test.IsSolved(newWrapMux3(), &wrapMux3{Sel: 1, In: in, Out0: 20}, field); err != nil {
		t.Fatalf("sanity: %v", err)
	}
}

// Decoy: IsLess is correct under its documented 64-bit precondition. The
// differential test against IsLessNative agrees on random and edge inputs.
func TestDecoy_IsLessDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	cases := [][2]uint64{{0, 0}, {0, 1}, {1, 0}, {^uint64(0), ^uint64(0)}, {^uint64(0) - 1, ^uint64(0)}, {^uint64(0), 0}}
	for i := 0; i < 64; i++ {
		cases = append(cases, [2]uint64{rng.Uint64(), rng.Uint64()})
	}
	for _, c := range cases {
		a := &wrapIsLess{A: c[0], B: c[1], Out0: IsLessNative(c[0], c[1])}
		if err := test.IsSolved(newWrapIsLess(), a, field); err != nil {
			t.Fatalf("IsLess(%d, %d) disagrees with IsLessNative: %v", c[0], c[1], err)
		}
	}
}

// Decoy: DivMod agrees with DivModNative on honest inputs (the bug above
// needs a malicious prover; a differential test alone does not show it).
func TestDecoy_DivModDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 64; i++ {
		a, b := rng.Uint64(), rng.Uint64()>>uint(rng.Intn(64))|1
		q, r := DivModNative(a, b)
		if err := test.IsSolved(newWrapDivMod(), &wrapDivMod{A: a, B: b, Out0: q, Out1: r}, field); err != nil {
			t.Fatalf("DivMod(%d, %d): %v", a, b, err)
		}
	}
}

// Decoy: AssertRange rejects 2^n and accepts 2^n - 1.
func TestDecoy_AssertRangeBounds(t *testing.T) {
	shape := func() *wrapAssertRange { c := newWrapAssertRange(); c.NbBits = 8; return c }
	ok := shape()
	ok.V = 255
	if err := test.IsSolved(shape(), ok, field); err != nil {
		t.Fatalf("255 fits 8 bits: %v", err)
	}
	bad := shape()
	bad.V = 256
	if err := test.IsSolved(shape(), bad, field); err == nil {
		t.Fatal("256 does not fit 8 bits and must be rejected")
	}
}
