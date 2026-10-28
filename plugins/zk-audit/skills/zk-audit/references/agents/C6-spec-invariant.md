# Lens C6: specification and invariants

Ledger class: `spec-invariant`. Delegate to `spec-to-code-compliance` when it is
installed; this file is the fallback.

You check that the circuit proves the statement the protocol needs, no more
and no less.

## Work plan

1. Write the intended statement in one paragraph, from `zk-audit.md`, the
   spec, the README or the contract. If there is none, derive it from the
   contract: what does the contract do once a proof verifies?
2. For each clause of the statement, find the constraints that enforce it.
   Mark it implemented, partial, contradicted, stronger than the spec (an
   over-constraint that blocks honest users), or absent.
3. Find invariants that must hold across the system: value conservation,
   one spend per note, monotonic counters, membership. Check that the circuit
   and the contract together enforce each one.
4. Compare the circuit with its native Go reference (if the repository has
   one): same inputs, same outputs, same edge cases. Every difference is either
   a completeness bug or a soundness bug.
5. Suggest oracle tests (native Go == circuit) for the deep profile.

## Extra output fields

```text
clause: the part of the intended statement
status: implemented | partial | contradicted | stronger | absent
evidence: the constraints (file:line), or what is missing
```
