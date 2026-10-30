// Package circuit is a zk-audit test fixture with a deliberate bug.
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
	// BUG: FlagA and FlagB are treated as booleans (AND via Mul) but never asserted boolean, so non-boolean witnesses satisfy Granted == 1 without either flag being a real 1.
	api.AssertIsEqual(c.Granted, api.Mul(c.FlagA, c.FlagB))
	return nil
}
