// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(scoreHint) }

// scoreHint derives a reputation score from a secret seed.
func scoreHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Add(inputs[0], big.NewInt(1))
	outputs[0].Mod(outputs[0], big.NewInt(1000))
	return nil
}

// Attestation proves that Score is the reputation derived from a secret Seed.
type Attestation struct {
	Score frontend.Variable `gnark:",public"`
	Seed  frontend.Variable
}

// Define declares the constraints.
func (c *Attestation) Define(api frontend.API) error {
	out, err := api.Compiler().NewHint(scoreHint, 1, c.Seed)
	if err != nil {
		return err
	}
	// BUG: Score is taken from a hint of Seed, but no constraint ties the hint
	// output to Seed. The prover can publish any Score for any Seed.
	api.AssertIsEqual(c.Score, out[0])
	return nil
}
