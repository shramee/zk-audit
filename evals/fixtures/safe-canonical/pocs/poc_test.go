// Safe-fixture test for safe-canonical: the top bit is a deterministic function
// of Value, so a prover cannot choose Positive; the non-canonical alternative
// is impossible because ToBinary enforces the canonical (< r) decomposition.
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func TestDecoy_TopBitDeterministic(t *testing.T) {
	// Value = 2: canonical top bit is 0.
	if err := test.IsSolved(&Sign{}, &Sign{Value: 2, Positive: 0}, field); err != nil {
		t.Fatalf("sanity: the canonical top bit of 2 is 0: %v", err)
	}
	// Claiming the flipped top bit (as Value+r would give) is rejected.
	if err := test.IsSolved(&Sign{}, &Sign{Value: 2, Positive: 1}, field); err == nil {
		t.Fatal("a flipped top bit must be rejected under the canonical check")
	}
}
