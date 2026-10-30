// Eval PoC for the onehot-nonunique fixture (gnark v0.14.0).
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_MultiSelect: the one-hot selector's sum is not pinned to 1, so a
// prover activates several rows and Out is their sum, not a single table entry
// (T-INVALID-ASSIGNMENT).
func TestPoC_MultiSelect(t *testing.T) {
	tbl := [Size]frontend.Variable{10, 20, 30, 40}
	// Select rows 0 and 3: Out = 10 + 40 = 50, which is no single entry.
	attack := &Router{Table: tbl, Selector: [Size]frontend.Variable{1, 0, 0, 1}, Out: 50}
	if err := test.IsSolved(&Router{}, attack, field); err != nil {
		t.Fatalf("attack: selecting two rows should satisfy the circuit: %v", err)
	}
	// Sanity: a genuine one-hot selection yields that entry.
	ok := &Router{Table: tbl, Selector: [Size]frontend.Variable{0, 1, 0, 0}, Out: 20}
	if err := test.IsSolved(&Router{}, ok, field); err != nil {
		t.Fatalf("sanity: one-hot selection of row 1: %v", err)
	}
	// Control: a single-select claim with the wrong value is rejected.
	bad := &Router{Table: tbl, Selector: [Size]frontend.Variable{0, 1, 0, 0}, Out: 21}
	if err := test.IsSolved(&Router{}, bad, field); err == nil {
		t.Fatal("control: Out must equal the selected entry")
	}
}
