// Package circuit is a zk-audit advisory-replay fixture: it pins a gnark
// release affected by a published advisory and exercises the affected gadget.
package circuit

import "github.com/consensys/gnark/frontend"

// Range proves that A is at most B.
type Range struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Range) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.A, c.B)
	return nil
}
