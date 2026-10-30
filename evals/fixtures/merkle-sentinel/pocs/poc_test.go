// Eval PoC for the merkle-sentinel fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
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

// fold hashes leaf up the path (leaf always the left input), returning the root.
func fold(leaf *big.Int, path [Depth]*big.Int) *big.Int {
	cur := leaf
	for i := 0; i < Depth; i++ {
		cur = mimc2(cur, path[i])
	}
	return cur
}

// TestPoC_EmptySlotMember: the sentinel leaf 0 (an unused slot) proves as a
// member, because the circuit never rejects Leaf == 0 (T-INVALID-ASSIGNMENT).
func TestPoC_EmptySlotMember(t *testing.T) {
	var path [Depth]*big.Int
	for i := range path {
		path[i] = big.NewInt(int64(100 + i))
	}
	root := fold(big.NewInt(0), path) // the root of a tree whose slot is empty
	var a Member
	a.Root = root
	a.Leaf = 0
	for i := range path {
		a.Path[i] = path[i]
	}
	if err := test.IsSolved(&Member{}, &a, field); err != nil {
		t.Fatalf("attack: the empty sentinel leaf should prove as a member: %v", err)
	}
	// Control: a non-member leaf with the same path is rejected.
	bad := a
	bad.Leaf = 42
	if err := test.IsSolved(&Member{}, &bad, field); err == nil {
		t.Fatal("control: a leaf the path does not hash to must be rejected")
	}
	// Sanity: a genuine non-zero leaf proves against its own root.
	var gp [Depth]*big.Int
	copy(gp[:], path[:])
	gr := fold(big.NewInt(7), gp)
	var ok Member
	ok.Root, ok.Leaf = gr, 7
	for i := range gp {
		ok.Path[i] = frontend.Variable(gp[i])
	}
	if err := test.IsSolved(&Member{}, &ok, field); err != nil {
		t.Fatalf("sanity: a real member must prove: %v", err)
	}
}
