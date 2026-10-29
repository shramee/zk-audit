// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Ticket binds a secret to a public Commit and is meant to be valid only in a
// given Epoch.
type Ticket struct {
	Commit frontend.Variable `gnark:",public"`
	Epoch  frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

// Define declares the constraints.
func (c *Ticket) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Secret)
	api.AssertIsEqual(h.Sum(), c.Commit)
	// BUG: Epoch is a public input that no constraint uses, so the prover sets it freely and the same ticket is valid in every epoch.
	return nil
}
