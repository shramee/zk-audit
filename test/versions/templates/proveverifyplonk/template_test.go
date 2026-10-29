package proveverifyplonk

// T-PROVE-VERIFY (PLONK, unsafekzg test SRS).

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func TestTemplate(t *testing.T) {
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&Circuit{A: 17, B: 5, Q: 2}, field)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := plonk.Prove(ccs, pk, w, backend.WithSolverOptions(solver.WithHints(divHint), solver.OverrideHint(solver.GetHintID(divHint), evilDiv)))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := plonk.Verify(proof, vk, pub); err != nil {
		t.Fatalf("attack: the forged proof should verify: %v", err)
	}
}
