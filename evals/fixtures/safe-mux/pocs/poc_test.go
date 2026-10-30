// Safe-fixture test for safe-mux: a non-boolean selector is rejected.
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func TestDecoy_NonBooleanSelectorRejected(t *testing.T) {
	if err := test.IsSolved(&Router{}, &Router{Lane0: 10, Lane1: 20, Out: 30, Select: 2}, field); err == nil {
		t.Fatal("a non-boolean selector must be rejected")
	}
	if err := test.IsSolved(&Router{}, &Router{Lane0: 10, Lane1: 20, Out: 20, Select: 1}, field); err != nil {
		t.Fatalf("sanity: Select 1 picks Lane1: %v", err)
	}
}
