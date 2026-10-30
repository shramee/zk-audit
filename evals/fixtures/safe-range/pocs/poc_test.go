// Safe-fixture test for safe-range: a near-field-order operand is rejected by
// the 32-bit range check before the bounded comparator.
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

func TestDecoy_HugeOperandRejected(t *testing.T) {
	huge := new(big.Int).Sub(field, big.NewInt(1)) // r-1
	if err := test.IsSolved(&Ledger{}, &Ledger{Balance: 0, Spend: huge}, field); err == nil {
		t.Fatal("a near-field-order Spend must be rejected by the range check")
	}
	if err := test.IsSolved(&Ledger{}, &Ledger{Balance: 10, Spend: 5}, field); err != nil {
		t.Fatalf("sanity: 5 <= 10: %v", err)
	}
	if err := test.IsSolved(&Ledger{}, &Ledger{Balance: 5, Spend: 10}, field); err == nil {
		t.Fatal("10 <= 5 must be rejected")
	}
}
