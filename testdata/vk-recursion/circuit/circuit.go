// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Aggregator verifies an inner Groth16 proof in-circuit.
type Aggregator struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`
}

// Define declares the constraints.
func (c *Aggregator) Define(api frontend.API) error {
	v, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	// BUG: VerifyingKey is a private witness and is never bound to a trusted key (e.g. by hashing it and checking against a public commitment), so a prover supplies the verifying key of a circuit they can satisfy and forges the inner proof.
	return v.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}
