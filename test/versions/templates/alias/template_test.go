package alias

// T-ALIAS: a full-width decomposition without the modulus check accepts
// the bits of a + r; the std hint is found by name.

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
)

type lowBit struct {
	X   frontend.Variable
	Low frontend.Variable `gnark:",public"`
}

func (c *lowBit) Define(api frontend.API) error {
	b := bits.ToBinary(api, c.X, bits.WithNbDigits(api.Compiler().FieldBitLen()), bits.OmitModulusCheck())
	api.AssertIsEqual(b[0], c.Low)
	return nil
}

func TestTemplate(t *testing.T) {
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &lowBit{})
	if err != nil {
		t.Fatal(err)
	}
	var target solver.Hint
	for _, h := range bits.GetHints() {
		if strings.HasSuffix(solver.GetHintName(h), ".nBits") {
			target = h
		}
	}
	if target == nil {
		t.Fatal("bits hint not found by name")
	}
	evil := func(mod *big.Int, in, out []*big.Int) error {
		v := new(big.Int).Add(in[0], mod) // the alias a + r
		for i := range out {
			out[i].SetUint64(uint64(v.Bit(i)))
		}
		return nil
	}
	w, err := frontend.NewWitness(&lowBit{X: 2, Low: 1}, field) // 2 is even
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(target), evil)); err != nil {
		t.Fatalf("attack: %v", err)
	}
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: the honest bits must reject Low = 1")
	}
}
