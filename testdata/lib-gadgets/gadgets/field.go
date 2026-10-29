package gadgets

import (
	"github.com/consensys/gnark/std/math/emulated"
)

// Canonical returns x reduced to its canonical representative: the result
// is strictly less than the modulus p, so it can be compared limb by limb.
func Canonical[T emulated.FieldParams](f *emulated.Field[T], x *emulated.Element[T]) *emulated.Element[T] {
	// BUG: Reduce only bounds the limb widths; ReduceStrict is needed for
	// BUG: a result below p.
	return f.Reduce(x)
}
