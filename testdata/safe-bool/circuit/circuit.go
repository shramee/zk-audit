// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import "github.com/consensys/gnark/frontend"

// Policy grants access when both flags are set: Granted = FlagA AND FlagB.
type Policy struct {
	FlagA   frontend.Variable
	FlagB   frontend.Variable
	Granted frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Policy) Define(api frontend.API) error {
	// OK: both flags are constrained boolean before the AND.
	api.AssertIsBoolean(c.FlagA)
	api.AssertIsBoolean(c.FlagB)
	api.AssertIsEqual(c.Granted, api.Mul(c.FlagA, c.FlagB))
	return nil
}
