package circuit

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// SigCircuit public witness order: PubKey_A_X, PubKey_A_Y, Msg.
type SigCircuit struct {
	PubKey eddsa.PublicKey   `gnark:",public"`
	Msg    frontend.Variable `gnark:",public"`
	Sig    eddsa.Signature
	Amount emulated.Element[emparams.Secp256k1Fr]
}

// Define verifies an EdDSA signature and squares an emulated amount.
func (c *SigCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	if err := eddsa.Verify(curve, c.Sig, c.Msg, c.PubKey, &h); err != nil {
		return err
	}
	f, err := emulated.NewField[emparams.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	sq := f.Mul(&c.Amount, &c.Amount)
	api.AssertIsDifferent(sq.Limbs[0], 0)
	return nil
}
