// Safe-fixture test for safe-revenue: with 64-bit factors the product cannot
// wrap, so a understated Revenue is rejected.
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func TestDecoy_WrapRejected(t *testing.T) {
	// Two 64-bit factors: the 128-bit product fits the field, so Revenue must
	// be the true integer product.
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)) // 2^64-1
	prod := new(big.Int).Mul(p, p)
	if err := test.IsSolved(&Invoice{}, &Invoice{Price: p, Quantity: p, Revenue: prod}, field); err != nil {
		t.Fatalf("sanity: the honest product must verify: %v", err)
	}
	wrong := new(big.Int).Sub(prod, big.NewInt(1))
	if err := test.IsSolved(&Invoice{}, &Invoice{Price: p, Quantity: p, Revenue: wrong}, field); err == nil {
		t.Fatal("an understated revenue must be rejected")
	}
	// A factor that does not fit 64 bits is rejected by the range check.
	big65 := new(big.Int).Lsh(big.NewInt(1), 64)
	if err := test.IsSolved(&Invoice{}, &Invoice{Price: big65, Quantity: 1, Revenue: big65}, field); err == nil {
		t.Fatal("a factor wider than 64 bits must be rejected")
	}
}
