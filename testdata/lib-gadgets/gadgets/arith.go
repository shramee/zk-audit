package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// DivMod returns q and r with a = q*b + r and 0 <= r < b. The caller must
// range-check a and b to 64 bits and ensure b is not zero.
func DivMod(api frontend.API, a, b frontend.Variable) (q, r frontend.Variable) {
	res, err := api.Compiler().NewHint(divModHint, 2, a, b)
	if err != nil {
		panic(err)
	}
	q, r = res[0], res[1]
	api.AssertIsEqual(a, api.Add(api.Mul(q, b), r))
	// BUG: r < b is never asserted, so (q-1, r+b) is accepted as well.
	return q, r
}

// IsLess returns 1 if a < b and 0 otherwise. The caller must ensure a and
// b are range-checked to 64 bits.
func IsLess(api frontend.API, a, b frontend.Variable) frontend.Variable {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	// OK: with a, b < 2^64 the difference a - b + 2^64 lies in (0, 2^65),
	// and its bit 64 is 1 exactly when a >= b.
	d := api.Add(api.Sub(a, b), two64)
	bs := api.ToBinary(d, 65)
	return api.Sub(1, bs[64])
}
