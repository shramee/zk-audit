// Safe-fixture test for safe-zero: forging the inverse to mark a nonzero value
// as blocked is rejected, because Value*blocked == 0 pins the inverse.
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

func TestDecoy_FalseZeroRejected(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Flag{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Flag{Value: 5, Blocked: 1}, field)
	if err != nil {
		t.Fatal(err)
	}
	forge := func(_ *big.Int, _, out []*big.Int) error { out[0].SetUint64(0); return nil }
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(invHint), forge)); err == nil {
		t.Fatal("a nonzero Value marked blocked must be rejected")
	}
	ok, err := frontend.NewWitness(&Flag{Value: 0, Blocked: 1}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: Value 0 is blocked: %v", err)
	}
}
