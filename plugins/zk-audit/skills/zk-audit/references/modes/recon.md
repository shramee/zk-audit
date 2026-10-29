# Recon mode

Entry points: `/zk-audit:recon [path ...]` (plugin install) or
`/zk-audit recon [path ...]` (any install). Scope is the given paths, else the
current repository. `{skill}` is the directory that holds the skill's
`SKILL.md`.

Parse the arguments first:
`{skill}/scripts/gnark-inventory args --repo <repo> --mode recon -- <arguments>`
(its `scope` and `out` are the inputs). Then follow `{skill}/SKILL.md` Phase 0 and Phase 1 only. Do not spawn hunting
agents and do not run PoCs.

Print, in this order:

1. The stack line and any matching gnark advisories with their required action.
2. The circuits table: circuit, file, public inputs in public-witness order.
3. `binding-table.md` with every unknown cell left as `?`.
4. Hint inventory: call site, hint function, outputs, and which outputs never
   reach a constraint (pre-flagged).
5. Footgun hits grouped by id, each with `file:line`.
6. Five to ten threat-model questions the code cannot answer (which VK is
   deployed, who runs setup, who may submit proofs, what binds a proof to a
   sender or chain).
7. The output directory path.

Offer to draft `zk-audit.md` for the repository root. Write it only if the
user says yes.
