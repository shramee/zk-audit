// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Register binds a public key (X, Y) to an identity commitment.
type Register struct {
	X        frontend.Variable `gnark:",public"`
	Y        frontend.Variable `gnark:",public"`
	Identity frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Register) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	// BUG: the public key is hashed into the identity but never asserted on the curve, so an off-curve or low-order point is registered as a valid key (the intended check is curve.AssertIsOnCurve).
	h.Write(c.X, c.Y)
	api.AssertIsEqual(h.Sum(), c.Identity)
	return nil
}
