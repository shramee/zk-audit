// Package circuit is a zk-audit test fixture. It contains deliberate bugs so
// that the inventory tool has something to find. Do not use it as an example.
package circuit

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
)

// Depth is the Merkle depth; Path holds the leaf plus Depth siblings.
const Depth = 3

func init() {
	solver.RegisterHint(divHint, splitHint)
}

// Note is nested in the witness; its fields inherit the parent's visibility.
type Note struct {
	Value frontend.Variable
	Owner frontend.Variable
}

// TransferCircuit public witness order (what the verifier contract must
// pass): Root, nf, Recipient, Fees_0, Fees_1, Out_Value, Out_Owner.
type TransferCircuit struct {
	Root      frontend.Variable    `gnark:",public"`
	Nullifier frontend.Variable    `gnark:"nf,public"`
	Recipient frontend.Variable    `gnark:",public"`
	Fees      [2]frontend.Variable `gnark:",public"`
	Out       Note                 `gnark:",public"`

	In     Note
	Secret frontend.Variable `gnark:",secret"`
	Path   [Depth + 1]frontend.Variable
	Index  frontend.Variable
	Extra  []frontend.Variable
	Debug  frontend.Variable `gnark:"-"`
}

// Define declares the circuit constraints.
func (c *TransferCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.Secret, c.Index)
	api.AssertIsEqual(h.Sum(), c.Nullifier)

	// BUG: the path ignores Index, so the leaf position is unbound.
	cur := c.Path[0]
	for i := 1; i < len(c.Path); i++ {
		h.Reset()
		h.Write(cur, c.Path[i])
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)

	// BUG: the remainder res[1] is never constrained.
	res, err := api.Compiler().NewHint(divHint, 2, c.In.Value, c.Out.Value)
	if err != nil {
		return err
	}
	q := res[0]
	_ = res[1]
	api.AssertIsEqual(api.Mul(q, c.Out.Value), c.In.Value)

	// OK: both limbs are range-checked and recomposed.
	limbs, err := api.Compiler().NewHint(splitHint, 2, c.In.Value)
	if err != nil {
		return err
	}
	api.AssertIsEqual(api.Add(limbs[0], api.Mul(limbs[1], 1<<32)), c.In.Value)
	bits.ToBinary(api, limbs[0], bits.WithNbDigits(32))
	bits.ToBinary(api, limbs[1], bits.WithNbDigits(32))

	// BUG: 0/0 leaves ratio unconstrained.
	ratio := api.DivUnchecked(c.Fees[0], c.Fees[1])
	api.AssertIsEqual(api.Mul(ratio, c.Fees[1]), c.Fees[0])

	// BUG: full-width decomposition without the alias check.
	_ = bits.ToBinary(api, c.Out.Owner, bits.OmitModulusCheck())

	// BUG: change wraps when Out.Value > In.Value.
	change := api.Sub(c.In.Value, c.Out.Value)
	api.AssertIsLessOrEqual(change, c.In.Value)

	// BUG: holds trivially when flag is 0.
	flag := api.IsZero(c.Index)
	api.AssertIsEqual(api.Mul(flag, api.Sub(c.In.Owner, c.Out.Owner)), 0)

	// BUG: predicate computed and dropped.
	api.IsZero(c.Recipient)

	// BUG: Go branch on a witness value runs at compile time.
	if c.Index == nil {
		return nil
	}
	for i := range c.Extra {
		api.AssertIsBoolean(c.Extra[i])
	}
	return nil
}

// decompose returns hint outputs to its caller without constraining them.
func decompose(api frontend.API, v frontend.Variable) []frontend.Variable {
	out, err := api.Compiler().NewHint(splitHint, 2, v)
	if err != nil {
		panic(err)
	}
	return out
}
