package hintoverride

// T-HINT-OVERRIDE: ccs.Solve with solver.OverrideHint.

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestTemplate(t *testing.T) {
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Circuit{A: 17, B: 5, Q: 2}, field)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(w, solver.WithHints(divHint), solver.OverrideHint(solver.GetHintID(divHint), evilDiv)); err != nil {
		t.Fatalf("attack: %v", err)
	}
	if _, err := ccs.Solve(w, solver.WithHints(divHint)); err == nil {
		t.Fatal("control: the honest hint must reject Q = 2")
	}
}
