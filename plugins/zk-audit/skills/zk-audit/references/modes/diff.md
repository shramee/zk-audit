# Diff mode

Entry points: `/zk-audit:diff <base>[..<head>]` (plugin install) or
`/zk-audit diff <base>[..<head>]` (any install). Default base: `origin/main`,
head: `HEAD`. `{skill}` is the directory that holds the skill's `SKILL.md`.

1. Compute the merge base: `git merge-base <base> <head>`. List changed files
   with `git diff --name-status <merge-base> <head>`.
2. Run Phase 0 on `<head>`. Run the inventory on both sides in scratch
   worktrees under the output directory, never in the user's checkout:

   ```bash
   git worktree add --detach <out>/base <merge-base>
   git worktree add --detach <out>/head <head>
   {skill}/scripts/gnark-inventory inventory --repo <out>/base --out <out>/inv-base
   {skill}/scripts/gnark-inventory inventory --repo <out>/head --out <out>/inv-head
   ```

3. Compare the two `inventory.json` files. Each of these is a high-risk
   trigger and must get a dedicated agent pass:
   - an `Assert*`, `ToBinary`, range-check or `AssertIsBoolean` call removed or
     moved under a Go `if`;
   - a public input added, removed, re-ordered, or its `gnark` tag changed;
   - a new hint, or a hint output that is no longer reached by a constraint;
   - a gnark or gnark-crypto version change in `go.mod`;
   - a regenerated `Verifier.sol`, a changed VK file, or a changed verifier
     address or setter;
   - a changed `verifyProof` / `Verify` call site or public-input array.
4. Run the standard profile restricted to changed files plus the circuits and
   contracts they touch. Delegate to `differential-review` if installed.
5. Report as usual; every finding names the commit and hunk that introduced it.
6. Remove the scratch worktrees at the end.
