package circuit

import "github.com/consensys/gnark/frontend"

// testCircuit only exists in tests.
type testCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *testCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	return nil
}
