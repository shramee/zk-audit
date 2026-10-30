// Safe-fixture test for safe-epoch: a ticket does not transfer across epochs,
// because Epoch is absorbed into the commitment.
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

func TestDecoy_CrossEpochRejected(t *testing.T) {
	commit := mimc2(big.NewInt(1234), big.NewInt(5)) // issued for epoch 5
	if err := test.IsSolved(&Ticket{}, &Ticket{Commit: commit, Epoch: 5, Secret: 1234}, field); err != nil {
		t.Fatalf("sanity: the ticket is valid in its epoch: %v", err)
	}
	if err := test.IsSolved(&Ticket{}, &Ticket{Commit: commit, Epoch: 6, Secret: 1234}, field); err == nil {
		t.Fatal("the ticket must not be valid in a different epoch")
	}
}
