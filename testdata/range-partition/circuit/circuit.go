// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Pack splits Packed into a 16-bit low part Lo and a high part Hi, and exposes
// Hi (used downstream as, say, a tier or page number).
type Pack struct {
	Packed frontend.Variable `gnark:",public"`
	HiOut  frontend.Variable `gnark:",public"`
	Lo     frontend.Variable
	Hi     frontend.Variable
}

// Define declares the constraints.
func (c *Pack) Define(api frontend.API) error {
	// BUG: Lo is bounded to 20 bits but the split point is 2^16, so Lo's range overlaps Hi's; a given Packed has several (Lo, Hi) splits and Hi is prover-chosen.
	bits.ToBinary(api, c.Lo, bits.WithNbDigits(20))
	bits.ToBinary(api, c.Hi, bits.WithNbDigits(16))
	api.AssertIsEqual(c.Packed, api.Add(c.Lo, api.Mul(c.Hi, 1<<16)))
	api.AssertIsEqual(c.HiOut, c.Hi)
	return nil
}
