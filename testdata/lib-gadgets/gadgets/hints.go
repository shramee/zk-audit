package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(bitsHint, divModHint)
}

// bitsHint returns the len(outputs) low bits of inputs[0].
func bitsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	for i := range outputs {
		outputs[i].SetUint64(uint64(inputs[0].Bit(i)))
	}
	return nil
}

// divModHint returns the quotient and remainder of inputs[0] / inputs[1].
func divModHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if inputs[1].Sign() == 0 {
		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		return nil
	}
	outputs[0].Quo(inputs[0], inputs[1])
	outputs[1].Rem(inputs[0], inputs[1])
	return nil
}
