package circuit

import "math/big"

// divHint returns the quotient and remainder of inputs[0] / inputs[1].
func divHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if inputs[1].Sign() == 0 {
		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		return nil
	}
	outputs[0].Quo(inputs[0], inputs[1])
	outputs[1].Rem(inputs[0], inputs[1])
	return nil
}

// splitHint splits inputs[0] into a low and a high 32-bit limb.
func splitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	mask := new(big.Int).Lsh(big.NewInt(1), 32)
	mask.Sub(mask, big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], 32)
	return nil
}
