package replacementhint

// T-ASSERT-OVERRIDE on the test engine: test.IsSolved with
// test.WithReplacementHint.

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/test"
)

func TestTemplate(t *testing.T) {
	field := ecc.BN254.ScalarField()
	if err := test.IsSolved(&Circuit{}, &Circuit{A: 17, B: 5, Q: 2}, field, test.WithReplacementHint(solver.GetHintID(divHint), evilDiv)); err != nil {
		t.Fatalf("attack: %v", err)
	}
	if err := test.IsSolved(&Circuit{}, &Circuit{A: 17, B: 5, Q: 2}, field); err == nil {
		t.Fatal("control: the honest hint must reject Q = 2")
	}
}
