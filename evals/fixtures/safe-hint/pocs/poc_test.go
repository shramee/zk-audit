// Safe-fixture test for safe-hint: the quotient-forging attack from the
// unsound counterpart is rejected because the remainder is range-checked.
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var field = ecc.BN254.ScalarField()

// TestDecoy_QuotientForgeRejected: forging quotient 4 for 17/5 with r = -3 mod p
// no longer solves, because r must be a 32-bit value below Size.
func TestDecoy_QuotientForgeRejected(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Batch{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Batch{Count: 17, Size: 5, Quotient: 4}, field)
	if err != nil {
		t.Fatal(err)
	}
	forge := func(mod *big.Int, in, out []*big.Int) error {
		out[0].SetUint64(4)
		out[1].Sub(in[0], new(big.Int).Mul(out[0], in[1]))
		out[1].Mod(out[1], mod)
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(euclid), forge)); err == nil {
		t.Fatal("forging the quotient must be rejected when the remainder is range-checked")
	}
	// Sanity: the honest quotient 3 solves.
	ok, err := frontend.NewWitness(&Batch{Count: 17, Size: 5, Quotient: 3}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: honest witness: %v", err)
	}
}
