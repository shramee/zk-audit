// Eval PoC for the boolean-missing fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_NonBooleanFlags: Granted == FlagA*FlagB with neither flag asserted
// boolean, so Granted = 1 is reached with non-boolean flags (e.g. 2 and 1/2),
// though neither flag is a real "true" (T-INVALID-ASSIGNMENT).
func TestPoC_NonBooleanFlags(t *testing.T) {
	half := new(big.Int).ModInverse(big.NewInt(2), field) // 1/2 mod r
	attack := &Policy{FlagA: 2, FlagB: half, Granted: 1}
	if err := test.IsSolved(&Policy{}, attack, field); err != nil {
		t.Fatalf("attack: non-boolean flags should satisfy Granted == 1: %v", err)
	}
	// Sanity: real booleans behave as expected.
	if err := test.IsSolved(&Policy{}, &Policy{FlagA: 1, FlagB: 1, Granted: 1}, field); err != nil {
		t.Fatalf("sanity: 1 AND 1 == 1: %v", err)
	}
	if err := test.IsSolved(&Policy{}, &Policy{FlagA: 1, FlagB: 0, Granted: 1}, field); err == nil {
		t.Fatal("control: 1 AND 0 must not grant")
	}
}
