package proveverify

// T-PROVE-VERIFY (Groth16): a proof of the false statement verifies.

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
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
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w, backend.WithSolverOptions(solver.WithHints(divHint), solver.OverrideHint(solver.GetHintID(divHint), evilDiv)))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("attack: the forged proof should verify: %v", err)
	}
}
