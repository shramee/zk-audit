package linkage

// T-LINKAGE: the public tag recomputed natively with the gnark-crypto hash
// the circuit uses singles out one candidate.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type tagCircuit struct {
	Key frontend.Variable
	Tag frontend.Variable `gnark:",public"`
}

func (c *tagCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Key) // no per-context input: the tag is a fingerprint of Key
	api.AssertIsEqual(h.Sum(), c.Tag)
	return nil
}

func publicTag(key int64) *big.Int {
	var e fr.Element
	e.SetInt64(key)
	b := e.Bytes()
	h := nativemimc.NewMiMC()
	h.Write(b[:])
	return new(big.Int).SetBytes(h.Sum(nil))
}

func TestTemplate(t *testing.T) {
	_ = divHint
	_ = evilDiv
	candidates := []int64{11, 22, 33, 44}
	real := 2
	observed := publicTag(candidates[real])
	// the circuit publishes exactly this tag for the real key
	if err := test.IsSolved(&tagCircuit{}, &tagCircuit{Key: candidates[real], Tag: observed}, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("native and in-circuit MiMC disagree: %v", err)
	}
	var matches []int
	for i, c := range candidates {
		if publicTag(c).Cmp(observed) == 0 {
			matches = append(matches, i)
		}
	}
	if len(matches) != 1 || matches[0] != real {
		t.Fatalf("expected the tag to single out candidate %d, got %v", real, matches)
	}
}
