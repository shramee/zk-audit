# Library mode

For a repository that exports gnark gadgets but has no production circuit
(no non-test `Define`) and no verifier contract: a gadget library, a fork of
gnark std, or one std package in the module cache. Its users call the
gadgets from their own circuits and trust the doc comments; library mode
audits each exported gadget against its doc.

Entry points: `/zk-audit library [path ...]` (the `library` profile), or
any audit whose Phase 0 `stack.json` says `library.mode: true`: preselect
`library` in the profile question and say why in one line
(`library.reason`). `{skill}` is the directory that holds the skill's
`SKILL.md`. Everything else in `SKILL.md` applies: hard rules, phases,
ledger, judging and the assembler.

## Phase 0 and Phase 1

1. `detect` and `preflight` as usual. A gnark std package audited in place
   (for example `…/gnark@v0.14.0/std/math/cmp`) is read through its
   enclosing `go.mod`: gnark at that version, its advisories, typed loading.
2. `inventory` writes the **exported-gadget inventory** (`inventory.json`
   `gadgets`, section "Exported gadgets" of `inventory.md`): per gadget its
   signature, doc, input flows (`constrained`, `hint-input`, `escapes`,
   `arithmetic-only`, `compile-time`), output sources (a hint output and
   whether a constraint reaches it, the inputs, or neither), the
   constraining calls including same-package helpers, the hint sites, the
   doc's promise and precondition sentences by property, and `doc_checks`.
3. The ledger has one `gadget:<pkg>.<Func>|doc-contract` unit per gadget
   (lens L1) and, with no production circuit, one `package:<dir>|<class>`
   unit per gadget package for each circuit lens class (C1-C6, PR1).
4. There is no binding table and no system map: write in `system-map.md`
   who calls the library (its README, examples, importers you can see) and
   what they rely on.

## Phase 2: hunt

`bundle --profile library` writes the L1 bundle and the circuit-lens and
circuit vector-scan bundles over the gadget packages. L1 checks every
gadget's promise against its constraints and lists undocumented
preconditions (`references/agents/L1-doc-contract.md`); G3 checks the
library's own compositions (a gadget feeding another a value that breaks
its precondition). `deep` also runs L1 when a repository with circuits
exports gadgets.

## Phase 4: prove, per gadget

1. Create the PoC worktree (`SKILL.md` hard rule 3), then the harness:

   ```bash
   {skill}/scripts/gnark-inventory harness --out <out> --gadget <G-id or pkg.Func>
   ```

   It writes `<out>/worktree/<pkg dir>/zkaudit_harness_<name>_test.go`: a
   wrapper circuit `wrap<Name>` whose `Define` calls the gadget, inputs as
   witness fields, compile-time parameters as `gnark:"-"` fields, outputs
   asserted equal to `Out<i>` fields, plus skipped skeletons. Set the shape
   (`new<Wrap>()`: slice lengths, bit widths) to what callers use. A gnark
   std package import-cycles with `gnark/test`: add `--external` (the
   `<pkg>_test` form; unexported hints are then found by name). Generic
   gadgets get `--emparams` (default `emparams.BN254Fp`).
2. Write the PoC from the skeleton: T-HINT-OVERRIDE for a hint output,
   T-INVALID-ASSIGNMENT for an assignment the doc rules out, T-PROVE-VERIFY
   for Critical / High (`references/poc-templates.md`, T-GADGET-HARNESS). A
   promise about the representation (canonical, reduced) needs a
   limb-by-limb output check: `Field.AssertIsEqual` compares modulo p.
3. **Differential test** (T-DIFFERENTIAL) for every gadget with a native
   reference (the library's Go code, gnark-crypto, `math/big`): random
   inputs below the documented bounds plus the edges (0, 1, the bounds,
   `r - 1`), the native outputs as `Out` fields, `test.IsSolved` must
   accept each case. A disagreement on an honest input is a completeness
   or correctness finding; agreement proves nothing about a malicious
   prover. Record the run on the gadget's unit
   (`ledger mark --unit <id> --notes "differential: 67 cases, 0 mismatches"`).
4. `deep` adds constraint-deletion mutants (T-DIFFERENTIAL, "Mutants"): a
   mutant the differential and harness tests do not reject marks a
   constraint no test exercises.

Run everything in the sandbox (`go -C <out>/worktree test -run 'PoC_|Diff_' ./<pkg>/`).

## Report

The assembler adds **Gadget contracts** to the coverage section: one row
per exported gadget with its promises, preconditions, doc checks, the
status of its doc-contract unit and the records it produced. Findings use
the usual sections; `location.scope` is the gadget name.
