package gadgets

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// useCircuit exercises the gadgets with honest inputs (a test circuit, not
// a production one).
type useCircuit struct {
	A, B frontend.Variable
	Q, R frontend.Variable `gnark:",public"`
}

func (c *useCircuit) Define(api frontend.API) error {
	AssertRange(api, c.A, 64)
	AssertRange(api, c.B, 64)
	q, r := DivMod(api, c.A, c.B)
	api.AssertIsEqual(q, c.Q)
	api.AssertIsEqual(r, c.R)
	return nil
}

func TestHonestDivMod(t *testing.T) {
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(&useCircuit{}, &useCircuit{A: 17, B: 5, Q: 3, R: 2}, ecc.BN254.ScalarField()))
}
