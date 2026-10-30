// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Invoice proves that Revenue is Price times Quantity for bounded factors.
type Invoice struct {
	Price    frontend.Variable `gnark:",public"`
	Quantity frontend.Variable `gnark:",public"`
	Revenue  frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Invoice) Define(api frontend.API) error {
	// OK: both factors are bounded to 64 bits, so the 128-bit product cannot
	// wrap the 254-bit scalar field and Revenue is the integer product.
	bits.ToBinary(api, c.Price, bits.WithNbDigits(64))
	bits.ToBinary(api, c.Quantity, bits.WithNbDigits(64))
	api.AssertIsEqual(c.Revenue, api.Mul(c.Price, c.Quantity))
	return nil
}
