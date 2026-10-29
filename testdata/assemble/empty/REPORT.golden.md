# ZK security review — edge

Rendered by `gnark-inventory assemble` from `findings.json` and `coverage-ledger.json`. Coverage statements come only from the ledger.

## 1. Scope

| | |
|---|---|
| Profile | quick |
| Run | 20261027-120000 |
| Commit | not recorded |
| Files reviewed | `c/edge.go` |
| Stack | not recorded (no stack.json) |
| Companions | not recorded |
| Agents | C1, V-range |
| Out of scope | none recorded |

## 2. Posture

_No posture summary was recorded in `findings.json`._

Totals: 0 confirmed · 0 needs validation · 0 leads · 0 rejected. Ledger: 2 of 3 applicable units examined.

The run recorded no findings: no candidate survived judging in the 2 covered units.

The absence of confirmed findings does not mean the code is free of bugs. Only the units listed as examined in section 10 were reviewed.

## 3. Findings

No confirmed findings in the examined units. Section 10 lists what was and was not examined.

## 4. Finding details

None.

## 5. Leads

None.

## 6. Needs validation

None.

## 7. Trusted parties

No trusted-party power was recorded.

The ledger has no `trusted-party` unit: the inventory found no privileged function, role or setup site.

## 8. Privacy

No privacy finding was recorded.

The privacy lens (PR1) is not part of the `quick` profile; privacy was examined only through other lenses' findings.

## 9. Hardening notes

None recorded.

## 10. Coverage

| Kind | Units | planned | in progress | covered | candidate | deferred | blocked | not applicable | out of scope |
|---|---|---|---|---|---|---|---|---|---|
| circuit | 3 | 0 | 0 | 2 | 0 | 1 | 0 | 0 | 0 |
| **total** | 3 | 0 | 0 | 2 | 0 | 1 | 0 | 0 | 0 |

Examined (covered): 2 of 3 applicable units (66%).

Units not examined:

- `circuit:Edge|field-arithmetic` — deferred — C3 is not in the quick profile

Rejected candidates: 0 (kept in `findings.json` so a later run does not raise them again).

Companions: not recorded.

Inventory load mode: not recorded (no `inventory.json`).

## 11. Not covered

This review never examines:

- gnark itself: its backends, gnark-crypto and the internals of std, beyond matching the pinned version against known advisories and checking the preconditions of the gadgets the circuits call;
- circuits written for other frameworks (Circom, Noir, Halo2), which are routed to companion skills or checked against the generic vectors only;
- cryptographic assumptions: hash, curve and pairing security, the soundness of the proof system, and trusted-setup ceremony transcripts;
- deployed state and infrastructure outside the repository: bytecode, verifying keys and owners on chain, servers, key management, and relayers, indexers and frontends as operated;
- economic, governance and MEV attacks beyond the listed vectors;
- formal verification: no property is proven.

In this run:

- lenses not part of the `quick` profile: C2, C3, C4, C5, C6, I2, I3, I4, PR1, V-liveness, V-privacy, G1, G3, A1, F1;
- ledger units not examined: 1 of 3 applicable (section 10);
- companions: not recorded.

> This review is a time-boxed, best-effort search for bugs by an automated
> agent. It is not a guarantee of security. Absence of a finding is not
> evidence of absence of bugs.
