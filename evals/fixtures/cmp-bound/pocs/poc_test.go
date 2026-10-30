// Eval PoC for the cmp-bound fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// TestPoC_ComparatorPreconditionBroken: the operands are not range-checked, so
// a Spend equal to the field element r-1 (numerically about the field order)
// passes "Spend <= Balance" against Balance = 0 (T-INVALID-ASSIGNMENT).
func TestPoC_ComparatorPreconditionBroken(t *testing.T) {
	huge := new(big.Int).Sub(field, big.NewInt(1)) // r-1 as a field element
	attack := &Ledger{Balance: 0, Spend: huge}
	if err := test.IsSolved(&Ledger{}, attack, field); err != nil {
		t.Fatalf("attack: a near-field-order Spend should pass <= Balance 0: %v", err)
	}
	// Sanity: honest small values compare correctly.
	if err := test.IsSolved(&Ledger{}, &Ledger{Balance: 10, Spend: 5}, field); err != nil {
		t.Fatalf("sanity: 5 <= 10: %v", err)
	}
	// Control: within range, 10 <= 5 is rejected.
	if err := test.IsSolved(&Ledger{}, &Ledger{Balance: 5, Spend: 10}, field); err == nil {
		t.Fatal("control: 10 <= 5 must be rejected")
	}
}
