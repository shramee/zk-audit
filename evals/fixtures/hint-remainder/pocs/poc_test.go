// Eval PoC for the hint-remainder fixture (gnark v0.14.0).
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var field = ecc.BN254.ScalarField()

// TestPoC_QuotientFree: Count = q*Size + r with r unbounded leaves the
// published Quotient free. 17/5 is really 3, but a prover can publish 4 by
// choosing r = -3 mod p (T-HINT-OVERRIDE).
func TestPoC_QuotientFree(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Batch{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Batch{Count: 17, Size: 5, Quotient: 4}, field)
	if err != nil {
		t.Fatal(err)
	}
	// Forge r so that 4*5 + r = 17, i.e. r = -3 mod p.
	forge := func(mod *big.Int, in, out []*big.Int) error {
		out[0].SetUint64(4)
		out[1].Sub(in[0], new(big.Int).Mul(out[0], in[1]))
		out[1].Mod(out[1], mod)
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(euclid), forge)); err != nil {
		t.Fatalf("attack: a wrong quotient should satisfy the circuit: %v", err)
	}
	// Control: the honest hint gives quotient 3, so Quotient 4 is rejected.
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: honest quotient is 3; 4 must be rejected")
	}
	// Sanity: the honest quotient solves.
	ok, err := frontend.NewWitness(&Batch{Count: 17, Size: 5, Quotient: 3}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: honest witness: %v", err)
	}
}
