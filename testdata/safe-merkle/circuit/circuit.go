// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Depth is the Merkle depth; empty tree slots use the sentinel value 0.
const Depth = 4

// Member proves that Leaf sits in the tree, excluding the empty sentinel.
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
	// OK: the empty sentinel 0 is rejected, so an unused slot is not a member.
	api.AssertIsDifferent(c.Leaf, 0)
	cur := c.Leaf
	for i := 0; i < Depth; i++ {
		h.Reset()
		h.Write(cur, c.Path[i])
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}
