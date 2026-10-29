// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Sign exposes the top bit of the canonical decomposition of Value.
type Sign struct {
	Value    frontend.Variable `gnark:",public"`
	Positive frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Sign) Define(api frontend.API) error {
	// OK: ToBinary at full width keeps the default modulus check, so the
	// decomposition is the unique canonical one and the top bit is a function
	// of Value (no Value / Value+r ambiguity).
	b := bits.ToBinary(api, c.Value)
	api.AssertIsEqual(c.Positive, b[len(b)-1])
	return nil
}
