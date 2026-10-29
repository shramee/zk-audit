// Command setup compiles the circuit and exports a verifier. Fixture only.
package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"example.com/pool/circuit"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&circuit.TransferCircuit{Extra: make([]frontend.Variable, 2)})
	if err != nil {
		panic(err)
	}
	// BUG: single-party setup outside tests.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	_ = pk
	out, err := os.Create("Verifier.sol")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	if err := vk.ExportSolidity(out); err != nil {
		panic(err)
	}
}
