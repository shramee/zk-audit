// Safe-fixture test for safe-bool: non-boolean flags are rejected.
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func TestDecoy_NonBooleanFlagsRejected(t *testing.T) {
	half := new(big.Int).ModInverse(big.NewInt(2), field)
	if err := test.IsSolved(&Policy{}, &Policy{FlagA: 2, FlagB: half, Granted: 1}, field); err == nil {
		t.Fatal("non-boolean flags must be rejected")
	}
	if err := test.IsSolved(&Policy{}, &Policy{FlagA: 1, FlagB: 1, Granted: 1}, field); err != nil {
		t.Fatalf("sanity: 1 AND 1 == 1: %v", err)
	}
}
