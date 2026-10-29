# Diff mode

Entry points: `/zk-audit:diff <base>[..<head>]` (plugin install) or
`/zk-audit diff <base>[..<head>]` (any install). Default base: `origin/main`,
head: `HEAD`. `{skill}` is the directory that holds the skill's `SKILL.md`.

0. Parse the arguments: `{skill}/scripts/gnark-inventory args --repo <repo> --mode diff -- <arguments>`.
   Its `diff.base`, `diff.head`, `scope` and `out` are the inputs below.
1. List the changes and the high-risk triggers with the tool (it reads git
   objects only; it never touches the working tree, the index or hooks):

   ```bash
   {skill}/scripts/gnark-inventory diff --repo <repo> --base <base> --head <head> --out <out>
   ```

   It compares the merge base of `<base>` and `<head>` with `<head>` and
   writes `<out>/diff.json` and `<out>/diff.md`. Each trigger has a kind, a
   file and line in `<head>`, a scope and a detail:
   - `constraint-removed`: an `Assert*` (or other constraint) call removed
     from a function, or its function removed;
   - `range-check-removed`: a `ToBinary`, range-checker `Check`,
     `AssertIsLessOrEqual`, `AssertIsBoolean` or similar call removed;
   - `constraint-now-conditional`: a constraint call moved under a Go `if`;
   - `public-input-changed`: a public input added, removed, re-ordered, or
     its `gnark` tag changed;
   - `hint-added`: a new `NewHint` call or hint registration;
   - `gnark-version-changed`: a gnark or gnark-crypto version change in a
     `go.mod`;
   - `verifier-contract-changed`: a generated verifier contract changed;
   - `verifying-key-changed`: a VK file changed;
   - `verify-call-changed`: a changed `verifyProof` / `verify` call site,
     verifier address or setter, or public-input array.
2. Run Phase 0 on `<head>`. For the inventory of both sides, use scratch
   worktrees under the output directory, never the user's checkout:

   ```bash
   git -C <repo> worktree add --detach <out>/base <merge-base>
   git -C <repo> worktree add --detach <out>/head <head>
   {skill}/scripts/gnark-inventory inventory --repo <out>/base --out <out>/inv-base
   {skill}/scripts/gnark-inventory inventory --repo <out>/head --out <out>/inv-head
   ```

3. Every trigger gets a dedicated agent pass. The tool does not detect a
   hint output that is no longer reached by a constraint: compare the hint
   tables of the two `inventory.md` files for that.
4. Run the standard profile restricted to changed files plus the circuits and
   contracts they touch. Delegate to `differential-review` if installed.
5. Report as usual; every finding names the commit and hunk that introduced it.
6. Remove the scratch worktrees at the end.
