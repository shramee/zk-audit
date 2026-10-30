// Eval PoC for the nonbool-mux fixture (gnark v0.14.0).
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_NonBooleanSelector: Select is not constrained boolean, so Out can be
// a value outside {Lane0, Lane1} (T-INVALID-ASSIGNMENT).
func TestPoC_NonBooleanSelector(t *testing.T) {
	// Select = 2: Out = 10 + 2*(20-10) = 30, which is neither lane.
	attack := &Router{Lane0: 10, Lane1: 20, Out: 30, Select: 2}
	if err := test.IsSolved(&Router{}, attack, field); err != nil {
		t.Fatalf("attack: a non-boolean selector should satisfy the circuit: %v", err)
	}
	if err := test.IsSolved(&Router{}, &Router{Lane0: 10, Lane1: 20, Out: 20, Select: 1}, field); err != nil {
		t.Fatalf("sanity: Select 1 picks Lane1: %v", err)
	}
	// Control: with a boolean selector Out must equal a lane.
	if err := test.IsSolved(&Router{}, &Router{Lane0: 10, Lane1: 20, Out: 30, Select: 1}, field); err == nil {
		t.Fatal("control: Select 1 must give Out = 20, not 30")
	}
}
