// Package circuit is a zk-audit test fixture with a deliberate bug.
package circuit

import "github.com/consensys/gnark/frontend"

// Vault authorizes a withdrawal when a quorum of approvals is met. Approvals is
// a variable-length slice fixed at compile time.
type Vault struct {
	Threshold frontend.Variable `gnark:",public"`
	Granted   frontend.Variable `gnark:",public"`
	Approvals []frontend.Variable
}

// Define declares the constraints.
func (c *Vault) Define(api frontend.API) error {
	sum := frontend.Variable(0)
	for _, a := range c.Approvals {
		api.AssertIsBoolean(a)
		sum = api.Add(sum, a)
	}
	// BUG: a Go branch on the compile-time slice length gates the quorum check, so the deployed shape (compiled with Approvals empty) emits no constraint and Granted is unconstrained.
	if len(c.Approvals) > 0 {
		api.AssertIsEqual(c.Granted, 1)
		api.AssertIsLessOrEqual(c.Threshold, sum)
	}
	return nil
}
