// Eval PoC for the range-partition fixture (gnark v0.14.0).
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_HighPartAmbiguous: Lo overlaps Hi's range, so the same Packed has two
// splits with different Hi, both accepted (T-INVALID-ASSIGNMENT).
func TestPoC_HighPartAmbiguous(t *testing.T) {
	// Packed = 65536. Canonical split: Lo=0, Hi=1.
	if err := test.IsSolved(&Pack{}, &Pack{Packed: 65536, HiOut: 1, Lo: 0, Hi: 1}, field); err != nil {
		t.Fatalf("sanity: canonical split Hi=1: %v", err)
	}
	// Alternate split of the same Packed: Lo=65536 (fits 20 bits), Hi=0.
	if err := test.IsSolved(&Pack{}, &Pack{Packed: 65536, HiOut: 0, Lo: 65536, Hi: 0}, field); err != nil {
		t.Fatalf("attack: an alternate split with Hi=0 should also satisfy: %v", err)
	}
	// Control: a Hi that does not match any valid split is rejected.
	if err := test.IsSolved(&Pack{}, &Pack{Packed: 65536, HiOut: 5, Lo: 0, Hi: 5}, field); err == nil {
		t.Fatal("control: Hi=5 does not split 65536")
	}
}
