// Package circuit is a zk-audit advisory-replay fixture: it pins a gnark
// release affected by a published advisory and exercises the affected gadget.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Square proves that Out is the square of a secret emulated Amount.
type Square struct {
	Amount emulated.Element[emparams.Secp256k1Fr]
	Out    emulated.Element[emparams.Secp256k1Fr] `gnark:",public"`
}

// Define declares the constraints.
func (c *Square) Define(api frontend.API) error {
	f, err := emulated.NewField[emparams.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	sq := f.Mul(&c.Amount, &c.Amount)
	f.AssertIsEqual(sq, &c.Out)
	return nil
}
