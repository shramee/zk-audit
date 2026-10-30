// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import "github.com/consensys/gnark/frontend"

// Size is the number of routes in the one-hot selector.
const Size = 4

// Router reads one value out of Table using a one-hot Selector and exposes it.
type Router struct {
	Table    [Size]frontend.Variable `gnark:",public"`
	Selector [Size]frontend.Variable
	Out      frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Router) Define(api frontend.API) error {
	out := frontend.Variable(0)
	for i := 0; i < Size; i++ {
		api.AssertIsBoolean(c.Selector[i])
		out = api.Add(out, api.Mul(c.Selector[i], c.Table[i]))
	}
	// BUG: the selector bits are boolean but their sum is never constrained to 1, so a prover selects several entries at once and Out becomes their sum.
	api.AssertIsEqual(c.Out, out)
	return nil
}
