// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(sqrtHint) }

// sqrtHint returns a square root of inputs[0] (best effort).
func sqrtHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Sqrt(inputs[0])
	return nil
}

// Root proves that RootVal is a square root of a public Square.
type Root struct {
	Square  frontend.Variable `gnark:",public"`
	RootVal frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Root) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(sqrtHint, 1, c.Square)
	if err != nil {
		return err
	}
	// BUG: RootVal is taken from the hint but never constrained by RootVal*RootVal == Square, so the published root is a free value.
	api.AssertIsEqual(c.RootVal, out[0])
	return nil
}
