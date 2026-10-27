---
description: "Run zk-audit recon only on a gnark repository: stack detection, advisory check, circuit and public-witness inventory, hint and footgun inventory, draft public-input binding table and system map, plus threat-model questions. No hunting agents; cheap first step before a full audit."
argument-hint: "[path ...]"
---

# zk-audit recon

Run the `zk-audit` skill in **recon** mode. Scope is `$ARGUMENTS` if given,
else the current repository.

Follow `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/SKILL.md` Phase 0 and Phase 1
only. Do not spawn hunting agents and do not run PoCs.

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
