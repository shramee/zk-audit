// Package circuit is a zk-audit test fixture with a deliberate bug.
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
	// BUG: Select is used as a mux weight without AssertIsBoolean, so the prover picks any Select and Out becomes any affine combination of the lanes.
	out := api.Add(c.Lane0, api.Mul(c.Select, api.Sub(c.Lane1, c.Lane0)))
	api.AssertIsEqual(c.Out, out)
	return nil
}
