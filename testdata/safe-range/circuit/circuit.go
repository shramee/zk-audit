// Package circuit is a zk-audit test fixture: a correctly constrained circuit.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

// Ledger proves that Spend does not exceed Balance.
type Ledger struct {
	Balance frontend.Variable `gnark:",public"`
	Spend   frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Ledger) Define(api frontend.API) error {
	// OK: both operands are range-checked to 32 bits before the bounded
	// comparator, so its precondition holds and the comparison is sound.
	bits.ToBinary(api, c.Balance, bits.WithNbDigits(32))
	bits.ToBinary(api, c.Spend, bits.WithNbDigits(32))
	cmp.NewBoundedComparator(api, new(big.Int).Lsh(big.NewInt(1), 32), false).AssertIsLessEq(c.Spend, c.Balance)
	return nil
}
