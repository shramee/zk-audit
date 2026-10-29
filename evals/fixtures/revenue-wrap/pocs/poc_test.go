// Eval PoC for the revenue-wrap fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_RevenueWraps: two 128-bit factors whose integer product exceeds r
// satisfy the circuit with a Revenue that is strictly below the true integer
// product Price*Quantity, so a consumer that reads Revenue as the integer
// product is defrauded (T-INVALID-ASSIGNMENT).
func TestPoC_RevenueWraps(t *testing.T) {
	half := new(big.Int).Lsh(big.NewInt(1), 127) // 2^127, fits 128 bits
	prod := new(big.Int).Mul(half, half)         // 2^254 > r
	wrapped := new(big.Int).Mod(prod, field)     // Revenue as a field element
	if wrapped.Cmp(prod) >= 0 {
		t.Fatal("harness: the field product must be below the integer product")
	}
	attack := &Invoice{Price: half, Quantity: half, Revenue: wrapped}
	if err := test.IsSolved(&Invoice{}, attack, field); err != nil {
		t.Fatalf("attack: a wrapped revenue should satisfy the circuit: %v", err)
	}
	// Control: an honest small invoice checks out, a wrong revenue does not.
	if err := test.IsSolved(&Invoice{}, &Invoice{Price: 1000, Quantity: 5, Revenue: 5000}, field); err != nil {
		t.Fatalf("sanity: 1000*5 = 5000: %v", err)
	}
	if err := test.IsSolved(&Invoice{}, &Invoice{Price: 1000, Quantity: 5, Revenue: 4999}, field); err == nil {
		t.Fatal("control: a wrong revenue must be rejected")
	}
}
