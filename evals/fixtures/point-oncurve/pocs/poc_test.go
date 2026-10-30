// Eval PoC for the point-oncurve fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func mimc2(a, b *big.Int) *big.Int {
	h := nativemimc.NewMiMC()
	for _, x := range []*big.Int{a, b} {
		var e fr.Element
		e.SetBigInt(x)
		bs := e.Bytes()
		h.Write(bs[:])
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// onCurve asserts (X, Y) is on the curve: the check the fixture omits.
type onCurve struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func (c *onCurve) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(twistededwards.Point{X: c.X, Y: c.Y})
	return nil
}

// TestPoC_OffCurveKeyRegistered: an off-curve point is registered as a valid
// public key because the fixture never asserts on-curve (T-INVALID-ASSIGNMENT).
func TestPoC_OffCurveKeyRegistered(t *testing.T) {
	// (3, 5) is not on the BN254 twisted-Edwards curve.
	id := mimc2(big.NewInt(3), big.NewInt(5))
	if err := test.IsSolved(&Register{}, &Register{X: 3, Y: 5, Identity: id}, field); err != nil {
		t.Fatalf("attack: an off-curve key should register: %v", err)
	}
	// The omitted check rejects (3,5)...
	if err := test.IsSolved(&onCurve{}, &onCurve{X: 3, Y: 5}, field); err == nil {
		t.Fatal("harness: (3,5) must be off-curve")
	}
	// ...and accepts the neutral element (0,1).
	if err := test.IsSolved(&onCurve{}, &onCurve{X: 0, Y: 1}, field); err != nil {
		t.Fatalf("sanity: (0,1) is on-curve: %v", err)
	}
}
