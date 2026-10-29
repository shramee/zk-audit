// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Depth is the Merkle depth; empty tree slots use the sentinel value 0.
const Depth = 4

// Member proves that Leaf sits in the tree rooted at Root, with Path siblings.
type Member struct {
	Root frontend.Variable `gnark:",public"`
	Leaf frontend.Variable `gnark:",public"`
	Path [Depth]frontend.Variable
}

// Define declares the constraints.
func (c *Member) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	cur := c.Leaf
	for i := 0; i < Depth; i++ {
		h.Reset()
		h.Write(cur, c.Path[i])
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	// BUG: unused tree slots are the sentinel 0, but the circuit never asserts Leaf != 0, so a prover proves membership of an empty slot.
	return nil
}
