package harness

// A one-gadget library for the harness check: QuoRem returns the
// quotient and remainder of n / d with 0 <= r < d.

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func quoRemHint(_ *big.Int, in, out []*big.Int) error {
	out[0].Quo(in[0], in[1])
	out[1].Rem(in[0], in[1])
	return nil
}

// QuoRem returns q and r with n = q*d + r and 0 <= r < d. The caller must
// range-check n and d to 64 bits.
func QuoRem(api frontend.API, n, d frontend.Variable) (q, r frontend.Variable) {
	res, err := api.Compiler().NewHint(quoRemHint, 2, n, d)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(n, api.Add(api.Mul(res[0], d), res[1]))
	api.AssertIsLessOrEqual(res[1], api.Sub(d, 1))
	return res[0], res[1]
}
