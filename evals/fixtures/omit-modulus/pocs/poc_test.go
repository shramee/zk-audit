// Eval PoC for the omit-modulus fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// assign builds a Sign witness whose bits are the Width low bits of raw and
// whose public Value is raw mod r. Positive is the top bit, as the circuit reads it.
func assign(raw *big.Int) *Sign {
	a := &Sign{Value: new(big.Int).Mod(raw, field)}
	for i := 0; i < Width; i++ {
		a.Bits[i] = int(raw.Bit(i))
	}
	a.Positive = a.Bits[Width-1]
	return a
}

// TestPoC_NonCanonicalDecomposition: for the same public Value, the prover can
// present the bits of Value or of Value+r. They differ in the top bit, so the
// published Positive flag is not a function of Value (T-INVALID-ASSIGNMENT).
func TestPoC_NonCanonicalDecomposition(t *testing.T) {
	value := big.NewInt(2)
	alt := new(big.Int).Add(value, field) // Value + r; same field element
	if alt.BitLen() > Width {
		t.Fatalf("harness: Value+r needs more than %d bits", Width)
	}
	canonical := assign(value)
	noncanon := assign(alt)
	if canonical.Value.(*big.Int).Cmp(noncanon.Value.(*big.Int)) != 0 {
		t.Fatal("harness: both witnesses must carry the same public Value")
	}
	if canonical.Positive.(int) == noncanon.Positive.(int) {
		t.Fatal("harness: the two decompositions should differ in the top bit")
	}
	for name, a := range map[string]*Sign{"canonical": canonical, "noncanonical": noncanon} {
		if err := test.IsSolved(&Sign{}, a, field); err != nil {
			t.Fatalf("%s: both decompositions of Value=2 must satisfy the circuit: %v", name, err)
		}
	}
}
