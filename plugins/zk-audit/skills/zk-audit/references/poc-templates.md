# PoC templates

The `PoC:` field of every attack vector names one of these templates. The
`poc-builder` agent copies the template into the **scratch worktree** (never the
user's checkout), fills in the circuit, the false statement and the malicious
values, and runs it in the skill's sandbox (no network, worktree the only
writable tree, cgo off, time and memory limits; `SKILL.md` hard rule 3):

```bash
{skill}/scripts/sandbox --rw <out>/worktree --ro <repo> -- go -C <out>/worktree test -count=1 -run 'PoC_' ./<pkg>/
```

The sandbox sets `GOFLAGS=-mod=mod` and `GOPROXY=off`.

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
| the contract (binding, replay, state, funds flow, signatures) | a Foundry test | T-FOUNDRY-VERIFIER / T-FOUNDRY-REPLAY |
| a verifier gnark did not generate (inputs, points, transcript) | a changed proof or input that still verifies | T-FOUNDRY-MALLEATE |
| a public value that singles out the user (privacy) | a candidate set with one match | T-LINKAGE |
| a root window or capacity an attacker can flush (liveness) | a front-run that makes an honest proof revert | T-FOUNDRY-STALE-ROOT |
| an exported gadget no production circuit calls (library mode) | the gadget's wrapper circuit from `gnark-inventory harness` | T-GADGET-HARNESS, then the template above that fits |
| a gadget with a native reference (library mode) | honest inputs on which gadget and reference disagree | T-DIFFERENTIAL |

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
and `poc.result: demonstrated_on_model` unless you also show that the model and the original emit the same constraints
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

Use for contract-side findings (binding, replay, state, funds flow, token
handling, reentrancy, signatures, initialisation) when `forge` is present.
Without `forge`, or without the solc version the target pins in the local
solc cache (`forge build --offline` fails), the result is `not_run` with that
reason: never install or download either during the audit.

**Which verifier.** Pick the first that fits and say which in `notes`:

1. **The real verifier with a real proof**, when the finding involves what
   the verifier accepts (the ABI, the input width, the inputs the caller
   builds). In the scratch worktree, write a Go test in the circuit's
   package that compiles the production circuit, runs `groth16.Setup` (or
   `plonk.Setup` with `unsafekzg`), writes `Verifier.sol` with
   `vk.ExportSolidity`, proves one honest witness and prints
   `proof.MarshalSolidity()` and the public inputs as hex. Run it through
   the sandbox, then paste the proof words into the Solidity test as
   constants. This verifier has a fresh VK, so check first that it has the
   committed verifier's structure:
   `{skill}/scripts/gnark-inventory verifier diff --a <out>/worktree/<Verifier.sol> --b <repo>/<committed verifier>`
   (the structure must match; the VK constants differ by construction).
   `gnark-inventory verifier regen --circuit <pkg>.<Type>` makes the same
   verifier without the proof.
2. **The committed verifier with a proof from the committed keys**, only
   when the proving key is in the repository (`verifier ceremony` lists key
   files).
3. **A mock** that accepts everything, when the bug lives in the caller and
   what the verifier accepts does not matter to it (a replay, a missing
   nullifier, a token transfer after the check). The mock must have the
   exact selector and input length the target calls (`inventory.json`
   `contracts.verify_calls[].target`).

**Where it goes.** The Foundry root is the target's (the directory with
`foundry.toml`) inside `<out>/worktree`. Put the test under its `test`
directory as `PoC_<finding-number>.t.sol`. Without a Foundry project, write
a minimal `<out>/worktree/foundry.toml` (`src`, `test`, `out`, `cache_path`
under the worktree, and the `solc_version` the contracts' pragma allows that
is in the local solc cache). The worktree has no forge-std unless the target
vendors it: declare the cheatcodes you use.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import {Target, ITargetVerifier} from "../src/Target.sol"; // the contract under test
import {Verifier} from "./Verifier.sol"; // option 1: the verifier gnark exported in the worktree

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function chainId(uint256) external;
    function warp(uint256) external;
}

// Option 3 only: same selector and input length as ITargetVerifier.
contract AcceptAll is ITargetVerifier { /* function verifyProof(...) external pure returns (bool) { return true; } */ }

contract PoC_<FindingID> {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    Target target;

    function setUp() public {
        target = new Target(ITargetVerifier(address(new Verifier())) /*, constructor args */);
    }

    // proof words from proof.MarshalSolidity(), public inputs from the same witness
    function proof() internal pure returns (uint256[8] memory p) { /* p[0] = 0x...; */ }

    function test_attack() public {
        // 1. honest user action (vm.prank(alice))
        // 2. attacker replays / front-runs / swaps inputs / re-enters (vm.prank(mallory))
        // 3. require() the state the protocol must forbid; revert("...") when it does not happen
    }
    function test_control() public { /* the same step 2 against the fixed shape is rejected (try/catch) */ }
    function test_sanity() public { /* the honest flow succeeds, so the contract under test is live */ }
}
```

Run it through the sandbox (no network, the worktree the only writable
tree):
`{skill}/scripts/sandbox --rw <out>/worktree --ro <repo> -- forge test --root <out>/worktree --offline --match-contract PoC_ -vv`
(add `--match-path` when the worktree has other test files). Record
`package` as the repository-relative Foundry root.

## T-FOUNDRY-STALE-ROOT

T-FOUNDRY-VERIFIER specialised for root windows and capacity (V-LV4,
V-LV5): an honest proof built against a recent root, and an attacker who
inserts enough leaves before it lands that the root leaves the window. It
needs no forge-std: declare the two cheatcodes it uses. Replace the verifier
with one that accepts everything only when, as here, the bug is in the
window and not in the proof system.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import {NoteMixer, IMixerVerifier} from "../src/NoteMixer.sol"; // the contract under test

interface Vm { function deal(address, uint256) external; function prank(address) external; }
contract AcceptAll is IMixerVerifier { /* same signature as the target's verifier, returns true */ }

contract PoC_StaleRoot {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    NoteMixer mixer;
    function setUp() public { mixer = new NoteMixer(new AcceptAll() /*, constructor args */); }

    function test_attack_frontRunEvictsPendingRoot() public {
        // 1. victim inserts and reads the root its proof uses
        // 2. attacker (vm.prank) inserts WINDOW leaves, the window size read from the contract
        // 3. the victim's withdrawal reverts with the contract's unknown-root error
        //    (try/catch Error(string) and compare the reason)
        // 4. the attacker withdraws its own leaves again: the cost is gas only
    }
    function test_control_noFrontRun() public { /* same withdrawal without step 2 succeeds */ }
    function test_sanity_windowMinusOne() public { /* WINDOW - 1 inserts keep the root valid */ }
}
```

The window-minus-one case pins the bound the finding states. For a
time-based window, advance time with `vm.warp` instead of inserting. Run it
like T-FOUNDRY-VERIFIER; with no forge-std in the worktree this file needs
no remapping.

## T-FOUNDRY-REPLAY

T-FOUNDRY-VERIFIER specialised for replay and front-running. Submit the same
proof and public inputs from a second address, on a second deployment, or
under a second `chainid` (`vm.chainId`), and show that both calls succeed or
that the second caller receives the funds.

## T-FOUNDRY-MALLEATE

T-FOUNDRY-VERIFIER for verifiers gnark did not generate, or edited after
generation (`attack-vectors/custom-verifiers.md`). It needs the verifier
under test and one valid proof for it: the repository's own test proof, or
a proof made with the generator's toolchain only if that toolchain is
already installed (never install it). Change one thing the verifier must
reject and show that it accepts it:

| Vector | Change | Accepted means |
|---|---|---|
| V-CV5 | public input `x` → `x + r` | inputs are not checked `< r` |
| V-CV6 | proof coordinate `y` → `y + q`, or a point → `(0, 0)` | coordinates or identity points are not checked |
| V-CV7 | append a word, or change the declared length | the encoding is malleable |
| V-CV2, V-CV1 | a proof word outside the hashed range | the transcript does not bind it |
| V-CV3, V-CV4 | a point off the curve, or a pairing input of another length | a failed precompile call is ignored |

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import {CustomVerifier} from "../src/CustomVerifier.sol"; // the verifier under test

contract PoC_<FindingID> {
    CustomVerifier v;
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public { v = new CustomVerifier(); }

    // the honest proof and its public inputs (from the repository's tests)
    function proof() internal pure returns (uint256[8] memory p) { /* p[0] = 0x...; */ }
    function inputs() internal pure returns (uint256[2] memory x) { /* x[0] = ...; */ }

    function test_sanity() public view {
        require(v.verifyProof(proof(), inputs()), "honest proof rejected");
    }
    function test_attack() public view {
        uint256[2] memory shifted = inputs();
        shifted[0] += R; // the changed value: another statement, same proof
        require(v.verifyProof(proof(), shifted), "changed input rejected: no bug on this path");
    }
    function test_control() public view {
        uint256[2] memory wrong = inputs();
        wrong[0] += 1; // a change the verifier must reject, and does
        require(!v.verifyProof(proof(), wrong), "verifier accepts anything: harness is wrong");
    }
}
```

Use try/catch instead of the returned bool for a verifier that reverts on
failure. Run it like T-FOUNDRY-VERIFIER. Name the consumer that keys state on
the changed value (a nullifier, a proof hash) in the finding; without one
the impact is malleability only.

## T-GADGET-HARNESS

Use in library mode: the gadget is exported and no production circuit
calls it, so there is no circuit to compile. Generate the wrapper into the
PoC worktree:

```bash
{skill}/scripts/gnark-inventory harness --out <out> --gadget <G-id or pkg.Func>
```

`zkaudit_harness_<name>_test.go` holds `wrap<Name>` (inputs as witness
fields, compile-time parameters as `gnark:"-"` fields, each output asserted
equal to an `Out<i>` field), `new<Wrap>()` for the shape, and skipped
skeletons of the honest control, the invalid assignment, one hint override
per hint the gadget creates and the differential test. Then apply the usual
template to the wrapper:

```go
// T-HINT-OVERRIDE through the wrapper: the doc of QuoRem promises 0 <= r < d
bad := &wrapQuoRem{N: 23, D: 4, Out0: 4, Out1: 7} // r = 7 >= d
evil := func(_ *big.Int, in, out []*big.Int) error {
	out[0].SetInt64(4)
	out[1].SetInt64(7)
	return nil
}
ccs, _ := frontend.Compile(field, r1cs.NewBuilder, newWrapQuoRem())
w, _ := frontend.NewWitness(bad, field)
_, err := ccs.Solve(w, solver.OverrideHint(solver.GetHintID(quoRemHint), evil)) // attack: nil
_, err = ccs.Solve(w)                                                           // control: error
```

- A promise about the representation (canonical, `< p`, reduced) needs
  the output compared limb by limb (`out.Limbs[i]`): `Field.AssertIsEqual`
  compares modulo p and hides the bug. Use the strict API
  (`ReduceStrict`) in the same wrapper as the control.
- A method gadget: the wrapper builds the object with `New<Type>(api)`;
  add the later calls a caller makes on the same object.
- A gnark std package (or any package that `gnark/test` imports)
  import-cycles with an in-package test: rerun with `--external`. Hints
  are then unexported; find them by name (T-HINT-OVERRIDE).
- Keep the shape the library's callers use (bit widths, slice lengths):
  `nbBits = 2` is a fine PoC only if callers may pass 2.

## T-DIFFERENTIAL

Use in library mode for every gadget with a native reference (the
library's own Go function, `gnark-crypto`, `math/big`). It finds
completeness and correctness bugs (an honest input the gadget gets wrong or
cannot prove); it does not find under-constraint, which needs a malicious
prover (T-GADGET-HARNESS).

```go
func TestDiff_LessThan(t *testing.T) {
	field := ecc.BN254.ScalarField()
	rng := rand.New(rand.NewSource(1))
	cases := [][2]uint64{{0, 0}, {0, 1}, {1, 0}, {^uint64(0), ^uint64(0)}} // edges first
	for i := 0; i < 64; i++ {
		cases = append(cases, [2]uint64{rng.Uint64(), rng.Uint64()})
	}
	for _, c := range cases {
		a := &wrapLessThan{X: c[0], Y: c[1], Out0: lessThanRef(c[0], c[1])}
		if err := test.IsSolved(newWrapLessThan(), a, field); err != nil {
			t.Fatalf("LessThan(%d, %d) disagrees with the reference: %v", c[0], c[1], err)
		}
	}
}
```

- Inputs: random values inside the documented domain, then the edges (0,
  1, every documented bound, `2^n - 1`, `r - 1`, the point at infinity).
  An input outside the documented domain tests a precondition, not the
  contract: report it under the precondition, not as a wrong result.
- `test.IsSolved` runs the test engine (fast, no setup). Use
  `test.NewAssert(t).ProverSucceeded(..., test.WithCurves(...))` once on a
  few cases to cover the real builders.
- Property tests: the same loop with a property instead of a reference
  (`FromBinary(ToBinary(x)) == x`, `Mul(Inverse(x), x) == 1` for x ≠ 0).
- **Mutants** (deep): copy the gadget into the worktree, delete one
  constraint at a time (`Assert*`, a range check, a recomposition), and
  rerun the harness and differential tests on each mutant. A mutant that
  every test still accepts marks a constraint no test exercises: write the
  PoC that needs it, or report the constraint as untested (hardening).
- Evidence: a disagreement on an honest input is `POC` for a completeness
  or correctness finding. Agreement is no evidence of soundness; record it
  in the gadget's ledger unit notes only.

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

## T-LINKAGE

Use for privacy findings where a public value identifies the user or links
two actions (V-PR1, V-PR2, V-PR3, V-PR7). Recompute the public value natively
for every candidate in a small, realistic candidate set (the addresses or
keys that interacted with the contract, the amounts in range, the decoys of a
set) and show that exactly one candidate matches what the proof published:

```go
	// candidates: public data an observer has (addresses, public keys, amounts)
	var matches []int
	for i, c := range candidates {
		if publicTag(c) == observedTag { // publicTag: the circuit's formula, computed natively
			matches = append(matches, i)
		}
	}
	if len(matches) != 1 || matches[0] != realIndex {
		t.Fatalf("expected the tag to single out candidate %d, got %v", realIndex, matches)
	}
```

The honest control is the fixed formula (the tag with the secret or the
per-context input mixed in) for which no candidate matches. Compute the hash
with the same gnark-crypto function the circuit uses and say so. When the
link needs chain data (timing, fee values, relayer logs), write the
correlation as `proof:` text and keep `evidence: ANALYSIS`.

## T-ANALYSIS

No runnable PoC is feasible: the deployed VK is unknown, a trusted setup is
assumed, or the bug needs chain state. Write the concrete witness or call
sequence as `proof:` text and set `evidence: ANALYSIS`. Most of these belong in
`needs_validation` with explicit blockers.
