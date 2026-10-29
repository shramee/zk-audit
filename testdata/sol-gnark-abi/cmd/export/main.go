// Command export compiles the redemption circuit, runs the key setup and
// writes the Solidity verifier and the verifying key.
package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"example.com/redeem/circuit"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RedeemCircuit{})
	if err != nil {
		panic(err)
	}
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	out, err := os.Create("Verifier.sol")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	if err := vk.ExportSolidity(out); err != nil {
		panic(err)
	}
	k, err := os.Create("verifier.vk")
	if err != nil {
		panic(err)
	}
	defer k.Close()
	if _, err := vk.WriteTo(k); err != nil {
		panic(err)
	}
}
