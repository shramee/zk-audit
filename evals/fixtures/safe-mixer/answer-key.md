# Answer key — safe-mixer fixture (all-safe)

Fixture: `testdata/safe-mixer` (gnark v0.14.0 circuit + Solidity mixer, Foundry).
A **correct** integration: the nullifier is recorded and required `< R`, the
root is checked against `knownRoots`, the input array matches the circuit's
public-witness order, and the recipient is bound.

There are **no planted items**; recall is undefined. Any `confirmed` or
`needs_validation` record is a **false positive**. The owner-only `addRoot`
(O1) is a legitimate trusted-party observation, not a vulnerability, and should
at most be a `lead` or hardening note. The Foundry test `test_SafeMixerRejectsAttacks`
shows the double-spend, aliasing, forged-root and front-run attacks are all
rejected.
