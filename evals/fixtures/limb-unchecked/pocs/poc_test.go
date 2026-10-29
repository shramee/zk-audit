// Eval PoC for the limb-unchecked fixture (gnark v0.14.0).
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

// TestPoC_HighLimbUnbounded: the high limb is not range-checked, so a prover
// represents a value far larger than 64 bits (T-HINT-OVERRIDE).
func TestPoC_HighLimbUnbounded(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Transfer{})
	if err != nil {
		t.Fatal(err)
	}
	// A 200-bit amount: its low 32 bits are 0, its high part is 2^168.
	amount := new(big.Int).Lsh(big.NewInt(1), 200)
	w, err := frontend.NewWitness(&Transfer{Amount: amount}, field)
	if err != nil {
		t.Fatal(err)
	}
	forge := func(_ *big.Int, in, out []*big.Int) error {
		out[0].SetUint64(0)   // low limb 0 (passes the 32-bit check)
		out[1].Rsh(in[0], 32) // high limb ~2^168, never range-checked
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(splitHint), forge)); err != nil {
		t.Fatalf("attack: a 200-bit amount should satisfy the circuit: %v", err)
	}
	// Sanity: a genuine 64-bit amount solves with the honest hint.
	ok, err := frontend.NewWitness(&Transfer{Amount: 1 << 40}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: a 64-bit amount: %v", err)
	}
}
