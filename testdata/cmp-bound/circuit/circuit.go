// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// Ledger proves that Spend does not exceed Balance.
type Ledger struct {
	Balance frontend.Variable `gnark:",public"`
	Spend   frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Ledger) Define(api frontend.API) error {
	// BUG: a bounded comparator assumes |Spend-Balance| <= 2^32, but the operands are never range-checked, so an operand near the field order breaks the precondition and the comparison returns a wrong result.
	cmp.NewBoundedComparator(api, new(big.Int).Lsh(big.NewInt(1), 32), false).AssertIsLessEq(c.Spend, c.Balance)
	return nil
}
