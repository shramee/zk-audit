// Eval PoC for the unused-public fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func mimc1(a *big.Int) *big.Int {
	h := nativemimc.NewMiMC()
	var e fr.Element
	e.SetBigInt(a)
	bs := e.Bytes()
	h.Write(bs[:])
	return new(big.Int).SetBytes(h.Sum(nil))
}

// TestPoC_EpochUnbound: Epoch is public but unconstrained, so one ticket is
// valid in any epoch (T-INVALID-ASSIGNMENT).
func TestPoC_EpochUnbound(t *testing.T) {
	commit := mimc1(big.NewInt(1234))
	for _, epoch := range []int64{0, 1, 999999} {
		a := &Ticket{Commit: commit, Epoch: epoch, Secret: 1234}
		if err := test.IsSolved(&Ticket{}, a, field); err != nil {
			t.Fatalf("attack: the ticket should be valid in epoch %d: %v", epoch, err)
		}
	}
	// Control: a wrong secret is still rejected (the Commit binding is live).
	if err := test.IsSolved(&Ticket{}, &Ticket{Commit: commit, Epoch: 1, Secret: 5}, field); err == nil {
		t.Fatal("control: a wrong secret must be rejected")
	}
}
