// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import "github.com/consensys/gnark/frontend"

// Router selects between two lanes by a witness selector.
type Router struct {
	Lane0  frontend.Variable `gnark:",public"`
	Lane1  frontend.Variable `gnark:",public"`
	Out    frontend.Variable `gnark:",public"`
	Select frontend.Variable
}

// Define declares the constraints.
func (c *Router) Define(api frontend.API) error {
	// OK: api.Select asserts the selector boolean, so Out is one of the lanes.
	api.AssertIsEqual(c.Out, api.Select(c.Select, c.Lane1, c.Lane0))
	return nil
}
