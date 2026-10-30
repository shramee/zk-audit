// Eval PoC for the go-branch-skip fixture (gnark v0.14.0).
package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var field = ecc.BN254.ScalarField()

// shapeN is the circuit shape compiled with n approval slots.
func shapeN(n int) *Vault { return &Vault{Approvals: make([]frontend.Variable, n)} }

// TestPoC_QuorumSkipped: the production shape compiles Approvals empty, so the
// Go branch drops the quorum check and authorization passes with no approvals
// (T-INVALID-ASSIGNMENT).
func TestPoC_QuorumSkipped(t *testing.T) {
	// Deployed shape: zero approval slots.
	attack := &Vault{Threshold: 100, Granted: 1, Approvals: []frontend.Variable{}}
	if err := test.IsSolved(shapeN(0), attack, field); err != nil {
		t.Fatalf("attack: with the empty-approvals shape, Granted=1 should pass with no quorum: %v", err)
	}
	// Control: a shape that compiles two approval slots DOES enforce the quorum,
	// so one approval below a threshold of 2 is rejected.
	bad := &Vault{Threshold: 2, Granted: 1, Approvals: []frontend.Variable{1, 0}}
	if err := test.IsSolved(shapeN(2), bad, field); err == nil {
		t.Fatal("control: the non-empty shape must enforce the quorum")
	}
	// Sanity: the non-empty shape accepts a met quorum.
	ok := &Vault{Threshold: 2, Granted: 1, Approvals: []frontend.Variable{1, 1}}
	if err := test.IsSolved(shapeN(2), ok, field); err != nil {
		t.Fatalf("sanity: a met quorum must pass: %v", err)
	}
}
