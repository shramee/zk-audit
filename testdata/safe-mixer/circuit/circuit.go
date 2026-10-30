// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Withdraw proves knowledge of a note (Secret) whose nullifier is published.
type Withdraw struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Recipient frontend.Variable `gnark:",public"`
	Value     frontend.Variable `gnark:",public"`
	Secret    frontend.Variable
}

// Define declares the constraints.
func (c *Withdraw) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Secret)
	api.AssertIsEqual(h.Sum(), c.Nullifier)
	return nil
}
