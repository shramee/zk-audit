// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(euclid) }

// euclid returns the quotient and remainder of inputs[0] / inputs[1].
func euclid(_ *big.Int, inputs, outputs []*big.Int) error {
	if inputs[1].Sign() == 0 {
		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		return nil
	}
	outputs[0].Quo(inputs[0], inputs[1])
	outputs[1].Rem(inputs[0], inputs[1])
	return nil
}

// Batch proves that Count tokens split into groups of Size leave Quotient
// full groups. Quotient is published and consumed by the caller.
type Batch struct {
	Count    frontend.Variable `gnark:",public"`
	Size     frontend.Variable `gnark:",public"`
	Quotient frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Batch) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(euclid, 2, c.Count, c.Size)
	if err != nil {
		return err
	}
	q, r := out[0], out[1]
	// BUG: Count == q*Size + r is the only check; r is never range-bounded, so every q has a matching r over the field.
	api.AssertIsEqual(api.Add(api.Mul(q, c.Size), r), c.Count)
	api.AssertIsEqual(c.Quotient, q)
	return nil
}
