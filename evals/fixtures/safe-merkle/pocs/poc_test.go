// Safe-fixture test for safe-merkle: the empty sentinel leaf 0 is rejected.
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

func TestDecoy_EmptySlotRejected(t *testing.T) {
	var path [Depth]*big.Int
	cur := big.NewInt(0)
	var a Member
	a.Leaf = 0
	for i := 0; i < Depth; i++ {
		path[i] = big.NewInt(int64(100 + i))
		a.Path[i] = path[i]
		cur = mimc2(cur, path[i])
	}
	a.Root = cur
	if err := test.IsSolved(&Member{}, &a, field); err == nil {
		t.Fatal("the empty sentinel leaf 0 must be rejected")
	}
	// Sanity: a real non-zero member proves.
	cur = big.NewInt(7)
	var ok Member
	ok.Leaf = 7
	for i := 0; i < Depth; i++ {
		ok.Path[i] = path[i]
		cur = mimc2(cur, path[i])
	}
	ok.Root = cur
	if err := test.IsSolved(&Member{}, &ok, field); err != nil {
		t.Fatalf("sanity: a real member must prove: %v", err)
	}
}
