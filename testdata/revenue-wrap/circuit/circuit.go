// Package circuit is a zk-audit test fixture with a deliberate bug.
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
	// OK: both factors are bounded to 128 bits.
	bits.ToBinary(api, c.Price, bits.WithNbDigits(128))
	bits.ToBinary(api, c.Quantity, bits.WithNbDigits(128))
	// BUG: api.Mul is a field multiplication; two 128-bit factors give a 256-bit product that wraps the 254-bit scalar field, so Revenue is the product modulo r, not the integer product.
	api.AssertIsEqual(c.Revenue, api.Mul(c.Price, c.Quantity))
	return nil
}
