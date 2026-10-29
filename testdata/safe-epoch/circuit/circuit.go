// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Ticket binds a secret and an Epoch to a public Commit.
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
	// OK: Epoch is absorbed into the commitment, so a ticket is valid only in
	// the epoch it was issued for.
	h.Write(c.Secret, c.Epoch)
	api.AssertIsEqual(h.Sum(), c.Commit)
	return nil
}
