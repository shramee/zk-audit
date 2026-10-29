// Package circuit is a zk-audit advisory-replay fixture: it pins a gnark
// release affected by a published advisory and exercises the affected gadget.
package circuit

import "github.com/consensys/gnark/frontend"

// Pledge commits to a private Secret and exposes a public function of it.
type Pledge struct {
	Secret frontend.Variable
	Out    frontend.Variable `gnark:",public"`
}

// Define declares the constraints.
func (c *Pledge) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return nil
	}
	cm, err := committer.Commit(c.Secret)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Out, api.Mul(cm, cm))
	return nil
}
