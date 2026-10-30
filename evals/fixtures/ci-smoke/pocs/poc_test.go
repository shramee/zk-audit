// Eval PoC for the ci-smoke fixture (gnark v0.14.0).
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

// TestPoC_RootUnconstrained: RootVal is never tied to Square by a squaring
// constraint, so a prover publishes any root (T-HINT-OVERRIDE).
func TestPoC_RootUnconstrained(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Root{})
	if err != nil {
		t.Fatal(err)
	}
	// Claim 99 is a square root of 16.
	w, err := frontend.NewWitness(&Root{Square: 16, RootVal: 99}, field)
	if err != nil {
		t.Fatal(err)
	}
	evil := func(_ *big.Int, _, out []*big.Int) error { out[0].SetUint64(99); return nil }
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(sqrtHint), evil)); err != nil {
		t.Fatalf("attack: an arbitrary root should satisfy the circuit: %v", err)
	}
	// Control: the honest hint gives 4, so RootVal 99 is rejected.
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: honest sqrt of 16 is 4; 99 must be rejected")
	}
}
