# zk-audit threat model

## Accepted risks

| Id | Party | Risk | Notes |
|---|---|---|---|
| AR-1 | owner | posts the Merkle roots of the deposit tree | governance |
| AR-2 | owner | pauses withdrawals | emergencies only |
| AR-3 | sequencer | orders withdrawals and can delay them | |

## Trusted parties

| Party | Trust | Powers | Notes |
|---|---|---|---|
| owner | trusted | posts roots, pauses, swaps the verifier | 2-of-3 multisig |
| sequencer | bounded | orders withdrawals | at most one block of delay |

## Out of scope

| Path or area | Reason |
|---|---|
| contracts/mocks/ | test helpers, never deployed |

## Prior findings

| Id | Fingerprint | Status | Title |
|---|---|---|---|
| PF-1 | `TransferCircuit\|Path[0]\|merkle-leaf-unbound` | fixed | Leaf not bound to the note |
| PF-2 | `Pool\|deposit\|amount-unchecked` | acknowledged | Deposit amount not checked |

## Deployment

| Fact | Value |
|---|---|
| chain ids | 1 |
| verifying key | keys/transfer.vk |
