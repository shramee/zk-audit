// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Width is the decomposition width (the BN254 scalar field is 254 bits).
const Width = 254

// Sign recomposes Value from prover-supplied bits and exposes the top bit.
type Sign struct {
	Bits     [Width]frontend.Variable
	Value    frontend.Variable `gnark:",public"`
	Positive frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Sign) Define(api frontend.API) error {
	one := big.NewInt(1)
	sum := frontend.Variable(0)
	for i := 0; i < Width; i++ {
		api.AssertIsBoolean(c.Bits[i])
		sum = api.Add(sum, api.Mul(c.Bits[i], new(big.Int).Lsh(one, uint(i))))
	}
	// BUG: the recomposition is checked over the field with no check that the bits are the canonical (< r) decomposition, so the bits of Value and of Value+r both recompose to Value and differ in the high bits, making Positive prover-chosen.
	api.AssertIsEqual(sum, c.Value)
	api.AssertIsEqual(c.Positive, c.Bits[Width-1])
	return nil
}
