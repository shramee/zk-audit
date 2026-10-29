package completeness

// T-COMPLETENESS: an honest edge case that cannot be proven.

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type inv struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *inv) Define(api frontend.API) error {
	// the protocol needs X = 0 to map to Y = 0, but Inverse(0) has no solution
	api.AssertIsEqual(api.Inverse(c.X), c.Y)
	return nil
}

func TestTemplate(t *testing.T) {
	_ = divHint
	_ = evilDiv
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &inv{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&inv{X: 0, Y: 0}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("expected the honest edge case to be unprovable")
	}
}
