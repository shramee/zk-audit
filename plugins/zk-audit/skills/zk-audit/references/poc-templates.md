# PoC templates

The `PoC:` field of every attack vector names one of these templates. The
`poc-builder` agent copies the template into the **scratch worktree** (never the
user's checkout), fills in the circuit, the false statement and the malicious
values, and runs it with a time limit and no network:

```bash
cd <out>/worktree && GOFLAGS=-mod=mod GOPROXY=off timeout 600 go test -run 'PoC_' -count=1 ./<pkg>/
```

`-mod=mod` is needed because `gnark/test` imports `testify`, which a target
that never imported `gnark/test` lacks in `go.mod`; with `GOPROXY=off` the go
command takes it from the module cache and edits only the worktree's
`go.mod`/`go.sum`. If the cache lacks it, use the `ccs.Solve` and
`groth16.Prove` forms (T-HINT-OVERRIDE, T-PROVE-VERIFY), which need no
`gnark/test`.

## Choosing a template

| The free value comes from | False statement shown by | Template |
|---|---|---|
| a hint output (yours or gnark std) | an overridden hint | T-HINT-OVERRIDE, then T-PROVE-VERIFY for Critical/High |
| the bits hint of a full-width decomposition | the alias `a + r` | T-ALIAS |
| a witness the prover assigns directly (unbound input, gated check, wrapped `Sub`, missing binding) | a hand-built assignment | T-INVALID-ASSIGNMENT, then T-PROVE-VERIFY for Critical/High |
| a solver-computed wire (`DivUnchecked(0, 0)`) | a model circuit | T-CONSTRAINT-MODEL (evidence stays `ANALYSIS`) |
| an honest input that cannot be proven | an honest witness that fails | T-COMPLETENESS |
| the contract (binding, replay, state) | a Foundry test | T-FOUNDRY-VERIFIER / T-FOUNDRY-REPLAY |

Practical rules (all learned on the eval fixtures):

- Put the test in the circuit's own package (`package circuit`, not
  `circuit_test`) so it can name unexported hints and types.
- Build the circuit value with the production shape: copy slice lengths from
  the code that calls `frontend.Compile` (for example a `cmd/setup`), not from
  tests.
- Assign every witness field, including ones the bug does not touch, with
  values that satisfy the rest of the circuit (non-zero divisors, booleans
  where `AssertIsBoolean` applies, values under range-check widths).
- When the circuit hashes, compute the public values natively with the
  matching gnark-crypto hash (`ecc/bn254/fr/mimc` for `std/hash/mimc` on
  BN254) and say so in the PoC.
- A free wire with no public consequence (an unused hint output) is shown by
  two accepted witnesses for the same public input, with the control that a
  neighbouring constrained wire is rejected.

Every PoC has three parts. Without all three the evidence is `ANALYSIS`, not
`POC`:

1. **Attack**: a statement that must be false is accepted (solver satisfied, or
   proof verifies).
2. **Honest control**: the same false statement is rejected with honest hints /
   honest inputs. This proves the PoC exercises the bug and not a broken
   harness.
3. **Sanity control**: a true statement still passes, so the circuit under test
   is the one that ships.

The Go templates were checked against gnark v0.14.0, and every API they use
exists in gnark v0.16.4 (`constraint/solver/options.go` `OverrideHint`,
`constraint/solver/hint.go` `GetHintID` / `GetHintName`,
`test/assert_options.go` `WithSolverOpts`, `backend/backend.go`
`WithSolverOptions`). Keep slice lengths in the circuit value identical to
production, or the compiled constraint system differs.

---

## T-HINT-OVERRIDE

Use when a hint output is under-constrained. Replace the hint with a malicious
one at solve time.

```go
func TestPoC_<FindingID>(t *testing.T) {
	field := ecc.BN254.ScalarField() // the production curve
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &MyCircuit{ /* production lengths */ })
	if err != nil {
		t.Fatal(err)
	}
	// an assignment whose public statement must be false
	w, err := frontend.NewWitness(&MyCircuit{ /* ... */ }, field)
	if err != nil {
		t.Fatal(err)
	}
	evil := func(mod *big.Int, in, out []*big.Int) error {
		// prover-chosen outputs that satisfy the constraints but break intent
		return nil
	}
	id := solver.GetHintID(myHint)
	if _, err := ccs.Solve(w, solver.OverrideHint(id, evil)); err != nil {
		t.Fatalf("attack: malicious hint should satisfy the constraints: %v", err)
	}
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("control: honest hint must reject the false statement")
	}
}
```

Use `scs.NewBuilder` instead of `r1cs.NewBuilder` for PLONK circuits. If the
hint is unexported in another package (for example gnark std), find it by name:

```go
var target solver.Hint
for _, h := range bits.GetHints() { // or the package's GetHints()
	if strings.HasSuffix(solver.GetHintName(h), ".nBits") {
		target = h
	}
}
```

## T-PROVE-VERIFY

Extends T-HINT-OVERRIDE end to end: a proof of the false statement verifies.
Use it for Critical / High findings, because it shows the verifier accepts.

```go
	pk, vk, err := groth16.Setup(ccs) // test-only single-party setup
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w, backend.WithSolverOptions(solver.OverrideHint(id, evil)))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("attack: forged proof should verify: %v", err)
	}
```

For PLONK use `plonk.Setup(ccs, srs, srsLagrange)` with
`unsafekzg.NewSRS(ccs)` (test only), then `plonk.Prove` / `plonk.Verify`.

## T-ASSERT-OVERRIDE

The same attack through gnark's test harness, which also round-trips
serialization. `NoTestEngine()` is required: the test engine runs the hint
registry itself.

```go
func TestPoC_<FindingID>(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&MyCircuit{}, &falseAssignment,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.NoFuzzing(), test.NoTestEngine(),
		test.WithSolverOpts(solver.OverrideHint(solver.GetHintID(myHint), evil)))
}
```

On gnark ≥ v0.15 the test engine can also replace a hint:
`test.IsSolved(&MyCircuit{}, &falseAssignment, field, test.WithReplacementHint(id, evil))`
(`test/engine.go`).

## T-ALIAS

Use for full-width decompositions without a modulus check (`a` and `a + r`).
It is T-HINT-OVERRIDE with the bits hint replaced by the bits of `a + r`:

```go
	evil := func(mod *big.Int, in, out []*big.Int) error {
		v := new(big.Int).Add(in[0], mod) // the alias a + r
		for i := range out {
			out[i].SetUint64(uint64(v.Bit(i)))
		}
		return nil
	}
```

For BN254, `r` is odd, so the low bit of the alias is the opposite of the low
bit of `a`. That gives a one-line false statement.

## T-INVALID-ASSIGNMENT

Use when no hint is involved: the bug is that a hand-built witness satisfies the
constraints. Examples are a wrapped `Sub`, an `S + order` signature, or an
unbound selector set to 0.

```go
func TestPoC_<FindingID>(t *testing.T) {
	assert := test.NewAssert(t)
	// the attack: this assignment encodes a false statement and must FAIL in a
	// sound circuit; ProverSucceeded shows it does not.
	assert.ProverSucceeded(&MyCircuit{}, &maliciousAssignment,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
	// control: a nearby assignment that the circuit does reject
	assert.ProverFailed(&MyCircuit{}, &rejectedAssignment,
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
```

## T-CONSTRAINT-MODEL

Use when the free value comes from the solver, not a hint, so no hook exists.
`api.DivUnchecked(0, 0)` is an example. Copy the gadget's constraints into a
small model circuit in the scratch worktree and expose the free wire through a
hint, then apply T-HINT-OVERRIDE to the model. Record `evidence: ANALYSIS`
unless you also show that the model and the original emit the same constraints
(same `ccs.GetNbConstraints()` for the gadget in isolation). Say in the finding
that the PoC is a model.

## T-COMPLETENESS

Use for completeness bugs: an honest prover cannot prove a true statement.

```go
	w, _ := frontend.NewWitness(&honestEdgeCaseAssignment, field)
	if _, err := ccs.Solve(w); err == nil {
		t.Fatal("expected the honest edge case to be unprovable")
	}
```

State the honest input that triggers it (zero, `r - 1`, point at infinity,
maximum length) and why the protocol needs it to be provable.

## T-FOUNDRY-VERIFIER

Use for contract-side findings, when `forge` is present. Prefer the real
generated verifier with a real proof (`proof.MarshalSolidity()` from
gnark's `backend/groth16/bn254/solidity.go`). Use a mock that returns success
only when the bug lives in the caller and the verifier is irrelevant to it.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {Pool} from "../src/Pool.sol";

contract AcceptAll { function verifyProof(bytes calldata, uint256[7] calldata) external pure {} }

contract PoC_<FindingID> is Test {
    function test_attack() public {
        Pool pool = new Pool(address(new AcceptAll()));
        // 1. honest user action
        // 2. attacker replays / front-runs / swaps inputs
        // 3. assert the state the protocol must forbid
    }
}
```

Run it inside the scratch worktree: `forge test --match-contract PoC_ -vv`.

## T-FOUNDRY-REPLAY

T-FOUNDRY-VERIFIER specialised for replay and front-running. Submit the same
proof and public inputs from a second address, on a second deployment, or
under a second `chainid` (`vm.chainId`), and show that both calls succeed or
that the second caller receives the funds.

## T-DOS

Use for availability findings in prover services (crafted VK or proof
deserialization, slow hints). Run the operation with a memory or time limit
and show that it is exceeded:

```go
	done := make(chan error, 1)
	go func() { _, err := vk.ReadFrom(bytes.NewReader(crafted)); done <- err }()
	select {
	case <-done:
		t.Fatal("expected the crafted input to stall or exhaust memory")
	case <-time.After(10 * time.Second):
	}
```

Never run a memory-exhaustion PoC without a container or `ulimit -v` limit.

## T-ANALYSIS

No runnable PoC is feasible: the deployed VK is unknown, a trusted setup is
assumed, or the bug needs chain state. Write the concrete witness or call
sequence as `proof:` text and set `evidence: ANALYSIS`. Most of these belong in
`needs_validation` with explicit blockers.
