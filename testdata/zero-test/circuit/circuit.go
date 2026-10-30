// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(invHint) }

// invHint returns the inverse of inputs[0], or 0 when inputs[0] is 0.
func invHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if inputs[0].Sign() == 0 {
		outputs[0].SetUint64(0)
		return nil
	}
	outputs[0].ModInverse(inputs[0], mod)
	return nil
}

// Flag proves whether Value is zero: Blocked is meant to be 1 iff Value == 0.
type Flag struct {
	Value   frontend.Variable `gnark:",public"`
	Blocked frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Flag) Define(api frontend.API) error {
	inv, err := api.Compiler().NewHint(invHint, 1, c.Value)
	if err != nil {
		return err
	}
	blocked := api.Sub(1, api.Mul(c.Value, inv[0]))
	// BUG: a sound zero test also asserts Value*blocked == 0 so inv is pinned to the real inverse; without it the prover forges inv and chooses blocked.
	api.AssertIsEqual(c.Blocked, blocked)
	return nil
}
