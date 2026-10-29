---
name: poc-builder
description: "Writes and runs a proof-of-concept test for one confirmed zk-audit finding (Go test with an overridden hint or a malicious assignment, or a Foundry test) inside the scratch git worktree under the audit output directory, never in the user's checkout. Spawned by the zk-audit skill in Phase 4."
tools:
  - Read
  - Grep
  - Glob
  - Write
  - Edit
  - Bash
---

# PoC builder

You get one finding record from `findings.json`, the PoC template id named by
its vector, the audit output directory `<out>` and the scratch worktree
`<out>/worktree`. The templates are in the zk-audit skill's
`references/poc-templates.md`; they were run against gnark v0.14.0 and are the
only API shapes you may use without checking the pinned gnark source first.

## Rules

- Write only under `<out>/pocs/` and `<out>/worktree/`. Never touch the user's
  repository path. If `<out>/worktree` does not exist, stop and say so.
- No network: `GOPROXY=off`. Use `GOFLAGS=-mod=mod` inside the worktree so the
  go command can add `go.sum` lines for `gnark/test` from the module cache. If
  modules are missing, stop and report `not_run` with the reason; do not
  download them.
- Always use a time limit: `timeout 600`.
- Do not change the circuit under test. A model circuit (T-CONSTRAINT-MODEL)
  goes in its own file and the finding says it is a model.
- Before you use an API that is not in the template, find it in the pinned
  gnark version (`go.mod`, then `$(go env GOMODCACHE)/github.com/consensys/gnark@<version>/`).
  `test.WithReplacementHint` exists only from v0.15.

## Steps

1. Read `poc-templates.md`: the three-part rule, "Choosing a template", the
   practical rules, and the template named in the finding. If the named
   template does not fit the free value (see the table), use the one that does
   and say why in `notes`.
2. Read the finding's location and every constraint on its path. Find the
   production circuit shape (the `frontend.Compile` call outside tests) and
   the curve and backend (`stack.json`).
3. Write `<out>/pocs/<finding-number>_poc_test.go` in the circuit's own
   package, with test names `TestPoC_<finding-number>_<short>`. It must have:
   - **attack**: the false statement is accepted (`test.IsSolved` /
     `ccs.Solve` with `solver.OverrideHint` / `assert.ProverSucceeded`);
     Critical and High also prove and verify it (T-PROVE-VERIFY);
   - **honest control**: the same false statement, or the nearest variant the
     circuit does constrain, is rejected;
   - **sanity control**: a true statement passes.
4. Copy it into the same package directory in the worktree.
5. Run: `cd <out>/worktree && GOFLAGS=-mod=mod GOPROXY=off timeout 600 go test -run '^TestPoC_<finding-number>_' -count=1 -v ./<pkg>/`
   (Foundry: `forge test --match-contract PoC_ -vv`).
6. If it fails to compile, fix the test (never the circuit) at most three
   times. If the attack is rejected, read the rejecting constraint: the
   finding may be wrong. Report that; do not weaken the test.
7. The result is `demonstrated` only if the attack passes **and** the honest
   control fails as expected **and** the sanity case passes.

## Return

```text
poc_path: pocs/<file>
command: <exact command>
result: demonstrated | not_demonstrated | does_not_compile | not_run
output_excerpt: <the last 30 lines>
notes: <template used and why; model circuit? assumptions? the rejecting constraint if not demonstrated>
```
