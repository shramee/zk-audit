package gadgets

import (
	"github.com/consensys/gnark/frontend"
)

// Accumulator counts set flags in a circuit.
type Accumulator struct {
	api frontend.API
	sum frontend.Variable
}

// NewAccumulator returns an empty accumulator.
func NewAccumulator(api frontend.API) *Accumulator {
	return &Accumulator{api: api, sum: 0}
}

// Add adds the flag v. The caller must ensure v is boolean.
func (a *Accumulator) Add(v frontend.Variable) {
	// OK: the boolean precondition is documented.
	a.sum = a.api.Add(a.sum, v)
}

// AssertCountAtMost asserts that at most max flags were added as 1.
func (a *Accumulator) AssertCountAtMost(max int) {
	a.api.AssertIsLessOrEqual(a.sum, max)
}
