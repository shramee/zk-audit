package invalidassignment

// T-INVALID-ASSIGNMENT: a hand-built witness for a wrapped Sub.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type change struct {
	In, Out frontend.Variable
	Change  frontend.Variable `gnark:",public"`
}

func (c *change) Define(api frontend.API) error {
	api.AssertIsEqual(api.Sub(c.In, c.Out), c.Change)
	return nil
}

func TestTemplate(t *testing.T) {
	_ = divHint
	_ = evilDiv
	rMinus1 := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	assert := test.NewAssert(t)
	// the attack: Out > In wraps to r - 1
	assert.ProverSucceeded(&change{}, &change{In: 1, Out: 2, Change: rMinus1},
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
	// control: a nearby assignment the circuit rejects
	assert.ProverFailed(&change{}, &change{In: 1, Out: 2, Change: 5},
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
