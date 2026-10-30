// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func init() { solver.RegisterHint(euclid) }

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

// Batch proves that Count tokens split into groups of Size leave Quotient full
// groups, with a remainder strictly below Size.
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
	// OK: Count, Size and r are bounded to 32 bits and r < Size, so (q, r) is
	// the unique Euclidean decomposition and Quotient is pinned.
	bits.ToBinary(api, c.Size, bits.WithNbDigits(32))
	bits.ToBinary(api, r, bits.WithNbDigits(32))
	api.AssertIsLessOrEqual(r, api.Sub(c.Size, 1))
	api.AssertIsEqual(api.Add(api.Mul(q, c.Size), r), c.Count)
	api.AssertIsEqual(c.Quotient, q)
	return nil
}
