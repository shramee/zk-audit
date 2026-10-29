package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// ToBits returns the nbBits little-endian bits of v. Every returned value
// is boolean and the bits recompose to v, so v < 2^nbBits.
func ToBits(api frontend.API, v frontend.Variable, nbBits int) []frontend.Variable {
	out, err := api.Compiler().NewHint(bitsHint, nbBits, v)
	if err != nil {
		panic(err)
	}
	// BUG: no AssertIsBoolean on the outputs; the recomposition alone
	// BUG: accepts values such as (3, r-1) for v = 1 and nbBits = 2.
	recompose(api, out, v)
	return out
}

// recompose asserts that sum(bits[i] * 2^i) equals v.
func recompose(api frontend.API, b []frontend.Variable, v frontend.Variable) {
	acc := frontend.Variable(0)
	for i := range b {
		acc = api.Add(acc, api.Mul(b[i], new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	api.AssertIsEqual(acc, v)
}

// AssertRange asserts that 0 <= v < 2^nbBits.
func AssertRange(api frontend.API, v frontend.Variable, nbBits int) {
	// OK: bits.ToBinary constrains every bit to be boolean and recomposes.
	bits.ToBinary(api, v, bits.WithNbDigits(nbBits))
}

// Mux3 returns in[sel] for sel in {0, 1, 2}.
func Mux3(api frontend.API, sel frontend.Variable, in [3]frontend.Variable) frontend.Variable {
	b := bits.ToBinary(api, sel, bits.WithNbDigits(2))
	// BUG: sel = 3 passes the two-bit decomposition and returns in[2]; the
	// BUG: doc neither rejects it nor asks the caller to keep sel <= 2.
	return api.Lookup2(b[0], b[1], in[0], in[1], in[2], in[2])
}
