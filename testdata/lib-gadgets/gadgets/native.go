package gadgets

// DivModNative is the reference implementation of DivMod for 64-bit
// operands.
func DivModNative(a, b uint64) (q, r uint64) {
	return a / b, a % b
}

// IsLessNative is the reference implementation of IsLess.
func IsLessNative(a, b uint64) uint64 {
	if a < b {
		return 1
	}
	return 0
}
