// Eval PoC for the hint-helper fixture (gnark v0.14.0).
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

// TestPoC_HelperUnconstrained: toByte returns unconstrained hint outputs, so
// the published Parity bit is free and Reading is never range-checked. A
// prover publishes Parity 0 for an odd Reading by forging the bit (T-HINT-OVERRIDE).
func TestPoC_HelperUnconstrained(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Meter{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Meter{Reading: 7, Parity: 0}, field)
	if err != nil {
		t.Fatal(err)
	}
	// Honest low bit of 7 is 1; forge the hint to report bit 0 as well.
	forge := func(_ *big.Int, _, out []*big.Int) error {
		for i := range out {
			out[i].SetUint64(0)
		}
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(bitsHint), forge)); err != nil {
		t.Fatalf("attack: a wrong parity should satisfy the circuit: %v", err)
	}
	// Control: the honest hint reports parity 1, so Parity 0 is rejected.
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: honest parity of 7 is 1; 0 must be rejected")
	}
	// Sanity: the honest parity solves.
	ok, err := frontend.NewWitness(&Meter{Reading: 7, Parity: 1}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: honest witness: %v", err)
	}
}
