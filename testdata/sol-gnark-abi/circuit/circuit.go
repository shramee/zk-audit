// Package circuit holds the redemption circuit.
package circuit

import "github.com/consensys/gnark/frontend"

// RedeemCircuit proves knowledge of a secret whose square links a tag to a root.
type RedeemCircuit struct {
	Tag    frontend.Variable `gnark:",public"`
	Root   frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

// Define declares the constraints.
func (c *RedeemCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Tag, api.Add(api.Mul(c.Secret, c.Secret), c.Root))
	return nil
}
