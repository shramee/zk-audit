// Package circuit is a zk-audit advisory-replay fixture: it pins a gnark
// release affected by a published advisory and exercises the affected gadget.
package circuit

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// Auth verifies an EdDSA signature over a message and derives a nullifier
// from the signature.
type Auth struct {
	Pub       eddsa.PublicKey   `gnark:",public"`
	Msg       frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Sig       eddsa.Signature
}

// Define declares the constraints.
func (c *Auth) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	if err := eddsa.Verify(curve, c.Sig, c.Msg, c.Pub, &h); err != nil {
		return err
	}
	// The nullifier is derived from the signature S component.
	h.Reset()
	h.Write(c.Sig.S)
	api.AssertIsEqual(h.Sum(), c.Nullifier)
	return nil
}
