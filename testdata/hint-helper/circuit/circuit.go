// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(bitsHint) }

// bitsHint returns the low 8 bits of inputs[0], most significant first.
func bitsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	for i := range outputs {
		outputs[i].SetUint64(uint64(inputs[0].Bit(len(outputs) - 1 - i)))
	}
	return nil
}

// toByte returns the 8 bit variables of v. Callers treat the result as a
// genuine bit decomposition of v.
func toByte(api frontend.API, v frontend.Variable) []frontend.Variable {
	out, err := api.Compiler().NewHint(bitsHint, 8, v)
	if err != nil {
		panic(err)
	}
	// BUG: toByte returns the hint outputs without asserting each is boolean
	// or that they recompose to v. Every caller assumes it did both.
	return out
}

// Meter proves that Reading fits in one byte and exposes its parity.
type Meter struct {
	Reading frontend.Variable `gnark:",public"`
	Parity  frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Meter) Define(api frontend.API) error {
	b := toByte(api, c.Reading)
	api.AssertIsEqual(c.Parity, b[7])
	return nil
}
