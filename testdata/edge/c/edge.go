// Package c holds witness-layout edge cases for the gnark-inventory tests.
// Fixture only.
package c

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/selector"
)

const (
	width = 2
	words = width * 3 // 6
)

// Point is used in arrays and slices of structs.
type Point struct {
	X, Y frontend.Variable
}

// Base is embedded: its fields are walked inline with the parent's visibility.
type Base struct {
	Epoch frontend.Variable
}

// Inherit carries the "inherit" option on a custom type.
type Inherit struct {
	Vals [2]frontend.Variable `gnark:",inherit"`
}

// EdgeCircuit exercises the schema walker.
type EdgeCircuit struct {
	Base    `gnark:",public"`
	Renamed frontend.Variable        `gnark:"renamed_input,public"`
	Words   [words]frontend.Variable `gnark:",public"`
	Pts     [2]Point                 `gnark:",public"`
	List    Inherit                  `gnark:",public"`
	Ptr     *Point
	Many    []Point
	Big     [300]Point
	Emu     emulated.Element[emparams.BN254Fp]
	hidden  frontend.Variable
	Any     interface{}
	Count   int
	Skip    [3]frontend.Variable `gnark:"-"`
	Both    frontend.Variable    `gnark:",secret,public"`
}

// Define keeps every field in use and adds a few hint patterns.
func (c *EdgeCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Epoch, c.Renamed)
	for i := range c.Words {
		api.AssertIsBoolean(c.Words[i])
	}
	// unknown output count; only index 0 is used and constrained
	n := len(c.Many)
	outs, err := api.Compiler().NewHint(nil, n, c.Renamed)
	if err != nil {
		return err
	}
	api.AssertIsEqual(outs[0], c.Renamed)
	// whole-slice constraint through a range loop
	vals, err := api.Compiler().NewHint(nil, 3, c.Renamed)
	if err != nil {
		return err
	}
	for _, v := range vals {
		bits.ToBinary(api, v, bits.WithNbDigits(8))
	}
	// discarded outputs
	_, err = api.Compiler().NewHint(nil, 1, c.Renamed)
	if err != nil {
		return err
	}
	// a closure that takes the API
	check := func(api frontend.API, a, b frontend.Variable) {
		api.AssertIsEqual(selector.Mux(api, a, b, b), b)
	}
	check(api, c.Pts[0].X, c.Pts[1].Y)
	if c.Count > 0 { // Go int: not a witness value
		api.AssertIsEqual(c.Both, 1)
	}
	f, err := emulated.NewField[emparams.BN254Fp](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Emu, &c.Emu)
	_ = c.Ptr
	_ = c.Big
	_ = c.Any
	_ = c.hidden
	_ = c.List
	return nil
}

// Gadget stores the API: its methods count as circuit code.
type Gadget struct {
	api frontend.API
	out []frontend.Variable
}

func (g *Gadget) split(v frontend.Variable) {
	res, err := g.api.Compiler().NewHint(nil, 2, v)
	if err != nil {
		panic(err)
	}
	g.out = res
	_ = g.api.DivUnchecked(res[0], res[1])
}
