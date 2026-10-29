package assertoverride

// T-ASSERT-OVERRIDE: gnark/test ProverSucceeded with NoTestEngine and
// WithSolverOpts(OverrideHint).

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/test"
)

func TestTemplate(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&Circuit{}, &Circuit{A: 17, B: 5, Q: 2},
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.NoFuzzing(), test.NoTestEngine(),
		test.WithSolverOpts(solver.WithHints(divHint), solver.OverrideHint(solver.GetHintID(divHint), evilDiv)))
}
