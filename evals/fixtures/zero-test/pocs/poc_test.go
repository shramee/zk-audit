// Eval PoC for the zero-test fixture (gnark v0.14.0).
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

// TestPoC_FalseZeroFlag: the zero test omits Value*Blocked == 0, so a prover
// forges inv and marks a nonzero Value as blocked (T-HINT-OVERRIDE).
func TestPoC_FalseZeroFlag(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Flag{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Flag{Value: 5, Blocked: 1}, field)
	if err != nil {
		t.Fatal(err)
	}
	forge := func(_ *big.Int, _, out []*big.Int) error { out[0].SetUint64(0); return nil }
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(invHint), forge)); err != nil {
		t.Fatalf("attack: a nonzero Value marked blocked should satisfy the circuit: %v", err)
	}
	// Control: with the honest inverse, Value 5 gives Blocked 0, so 1 is rejected.
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: Value 5 is not zero; Blocked 1 must be rejected")
	}
	// Sanity: Value 0 is genuinely blocked.
	ok, err := frontend.NewWitness(&Flag{Value: 0, Blocked: 1}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: Value 0 is blocked: %v", err)
	}
}
