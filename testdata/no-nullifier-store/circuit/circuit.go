// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Withdraw proves knowledge of a note (Secret) whose nullifier is published.
// Public witness order: Root, Nullifier, Recipient, Value.
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
	// Nullifier = MiMC(Secret); the note commitment is out of scope here.
	h.Write(c.Secret)
	api.AssertIsEqual(h.Sum(), c.Nullifier)
	return nil
}
