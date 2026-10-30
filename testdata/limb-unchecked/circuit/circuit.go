// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func init() { solver.RegisterHint(splitHint) }

// splitHint splits inputs[0] into a low and a high 32-bit limb.
func splitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	mask := new(big.Int).Lsh(big.NewInt(1), 32)
	mask.Sub(mask, big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], 32)
	return nil
}

// Transfer proves that Amount (a 64-bit value) equals its two limbs recomposed,
// and exposes it.
type Transfer struct {
	Amount frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Transfer) Define(api frontend.API) error {
	limbs, err := api.Compiler().NewHint(splitHint, 2, c.Amount)
	if err != nil {
		return err
	}
	// OK: the low limb is range-checked to 32 bits.
	bits.ToBinary(api, limbs[0], bits.WithNbDigits(32))
	// BUG: the high limb is never range-checked, so the recomposition holds for a high limb far wider than 32 bits and Amount is effectively unbounded.
	api.AssertIsEqual(c.Amount, api.Add(limbs[0], api.Mul(limbs[1], 1<<32)))
	return nil
}
