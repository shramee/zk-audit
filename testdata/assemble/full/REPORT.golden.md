# ZK security review — pool @ 3f9c2a1

Rendered by `gnark-inventory assemble` from `findings.json` and `coverage-ledger.json`. Coverage statements come only from the ledger.

## 1. Scope

| | |
|---|---|
| Profile | quick |
| Run | 20261027-101500 |
| Commit | `3f9c2a1b7d5e4f60718293a4b5c6d7e8f9012345` |
| Files reviewed | `circuit/hints.go` · `circuit/transfer.go` · `contracts/Pool.sol` |
| Stack | gnark v0.14.0 (advisories: 3) · groth16 · bn254 · solidity: yes · foundry: yes |
| Versions | `go.mod`: gnark v0.14.0, gnark-crypto v0.19.0, go 1.24.0 |
| Advisories | GHSA-7fx8-hmgc-82jp (high, fixed v0.16.4) · GHSA-3mvx-pp85-pm65 (critical, fixed v0.16.2) · GHSA-fwf3-jmp7-gmrj (moderate, fixed v0.16.0) |
| Companions | ✔ fp-check · ✖ circom-auditor · ✖ solidity-auditor |
| Agents | C1, I1, I3, V-hash, V-hints, V-prover, V-pubin, V-range, G2 |
| Out of scope | Verifier.sol internals: a stub, not a generated verifier · 1 ledger unit marked out_of_scope (section 8) |

## 2. Posture

Proofs gate withdrawals from a shared pool. The Merkle membership check does not bind the spent note to the leaf, so any prover can withdraw. The owner can swap the verifier at any time. The single most important action is to hash the note into the leaf and bind Index into the path.

Totals: 3 confirmed (1 critical, 1 high, 1 low) · 1 needs validation · 1 lead · 1 rejected. Ledger: 1 of 6 applicable units examined.

## 3. Findings

| # | Title | Severity | Confidence | Evidence | Detected by |
|---|---|---|---|---|---|
| 1 | Merkle leaf is not bound to the spent note [NEW] | critical | 95 | POC | C1, V-hash, G2 |
| 2 | Owner check is skipped when Index is non-zero | high | 85 | ANALYSIS | C1 |
| 3 | Remainder hint output is never constrained | low | 70 | ANALYSIS | C1, V-hints |

## 4. Finding details

### 1. Merkle leaf is not bound to the spent note [NEW]

`TransferCircuit.Define` · `circuit/transfer.go:52-58` · severity **critical** · confidence 95 · evidence **POC** · detected by C1, V-hash, G2 · vectors V-M1

Also at: `Pool.withdraw` `contracts/Pool.sol:52`

**Description.** Any prover proves membership of any existing leaf with a fresh Secret and withdraws any value.

**Constraint.** `circuit/transfer.go:52-58`

```go
	cur := c.Path[0]
	for i := 1; i < len(c.Path); i++ {
		h.Reset()
		h.Write(cur, c.Path[i])
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
```

**Attack witness.** Take any known leaf and its siblings; set Secret=1, Index=7, In.Value=Out.Value=10^18; the witness satisfies every constraint.

**Impact.** Any prover drains the pool.

**PoC.** `pocs/1_poc_test.go` — `go test -run PoC_1 -count=1 ./circuit/` → demonstrated.

```text
=== RUN   TestPoC_1
--- PASS: TestPoC_1 (0.41s)
PASS
```

**Fix.** Hash the note and Index into the leaf and select siblings by the Index bits.

Option A — bind the note

```diff
-	cur := c.Path[0]
+	h.Reset()
+	h.Write(c.In.Value, c.In.Owner, c.Secret)
+	cur := h.Sum()
+	api.AssertIsEqual(cur, c.Path[0])
```

Option B — use std/accumulator/merkle

```diff
+	proof := merkle.MerkleProof{RootHash: c.Root, Path: c.Path[:]}
+	proof.VerifyProof(api, &h, c.Index)
```

**Refuter.** exploitable — circuit/transfer.go:52 starts from Path[0]; nothing ties it to In or Secret. (by refuter)

### 2. Owner check is skipped when Index is non-zero

`TransferCircuit.Define` · `circuit/transfer.go:90-91` · severity **high** · confidence 85 · evidence **ANALYSIS** · detected by C1

**Description.** Any prover sets Index to 1 so flag is 0 and the owner equality holds trivially.

**Constraint.** `circuit/transfer.go:90-91`

```go
	flag := api.IsZero(c.Index)
	api.AssertIsEqual(api.Mul(flag, api.Sub(c.In.Owner, c.Out.Owner)), 0)
```

**Attack witness.** Index=1 → flag=0 → 0·(In.Owner − Out.Owner) = 0 for any owners.

**Impact.** Any prover moves a note to a new owner.

**Gates.** executes: flag=0 zeroes the product · reachable: Index is free · unprivileged: yes · impact: theft

**PoC.** none; evidence **ANALYSIS**.

**Fix.** Assert In.Owner == Out.Owner unconditionally, or derive the gate from a constrained bit.

**Chain.** `TransferCircuit|Path[0]|merkle-leaf-unbound`

**Refuter.** not exploitable — Out.Owner is not used by Pool.withdraw, so ownership has no on-chain effect.

### 3. Remainder hint output is never constrained

`TransferCircuit.Define` · `circuit/transfer.go:61-67` · severity **low** · confidence 70 · evidence **ANALYSIS** · detected by C1, V-hints · vectors V-H1

**Description.** The prover sets the divHint remainder to any value.

**Constraint.** `circuit/transfer.go:61-67`

```go
	res, err := api.Compiler().NewHint(divHint, 2, c.In.Value, c.Out.Value)
	if err != nil {
		return err
	}
	q := res[0]
	_ = res[1]
	api.AssertIsEqual(api.Mul(q, c.Out.Value), c.In.Value)
```

**Attack witness.** Override divHint to return (q, r) = (1, 12345); Solve still succeeds because res[1] is unused.

**Impact.** No direct impact today; any later use of res[1] is forgeable.

**PoC.** none; evidence **ANALYSIS**.

**Refuter.** not run.

## 5. Leads

Trails worth manual work. No severity, no fix.

- **Recipient is only fed to a discarded IsZero** — `Pool.withdraw` · `contracts/Pool.sol:45` · detected by I1, G2 — The circuit never relates Recipient to the note owner. Smells: api.IsZero(c.Recipient) result dropped; Recipient | appears in no AssertIsEqual. Unverified: whether the Groth16 IC term alone binds the recipient against front-running.

## 6. Needs validation

| Item | Severity | Confidence | Blockers | How to validate |
|---|---|---|---|---|
| **Keys come from a single-party Groth16 setup** · `cmd/setup/main.go:20` | high | 60 | which proving key backs the deployed verifier?; was a ceremony run? | Compare the deployed verifier's VK with the ceremony transcript. |

## 7. Hardening notes

- **Unused helper returns unconstrained hint outputs** — `circuit/transfer.go:106` — decompose is never called; delete it or constrain its outputs.
- **No test checks the public-input order against Pool.withdraw**

## 8. Coverage

| Kind | Units | planned | in progress | covered | candidate | deferred | blocked | not applicable | out of scope |
|---|---|---|---|---|---|---|---|---|---|
| circuit | 4 | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| public-input | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| contract-fn | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| verifier | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| prover | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| **total** | 8 | 1 | 0 | 1 | 2 | 1 | 1 | 1 | 1 |

Examined (covered): 1 of 6 applicable units (16%).

Units not examined:

- `circuit:TransferCircuit|hint-soundness` — candidate — raised TransferCircuit|res[1]|hint-output-unconstrained, TransferCircuit|Path[0]|merkle-leaf-unbound; not closed after judging
- `circuit:TransferCircuit|spec-invariant` — deferred — C6 is not in the quick profile
- `circuit:SigCircuit|crypto-gadgets` — planned — no reason recorded
- `public-input:TransferCircuit.Recipient|public-input-binding` — candidate — raised Pool|withdraw|recipient-not-constrained, Pool|withdraw|missing-fingerprint; not closed after judging
- `contract-fn:Pool.withdraw|protocol-state` — blocked — agent hit its turn limit

Units not applicable or out of scope:

- `prover:cmd/setup/main.go|prover-service` — not applicable — no prover service in the repository
- `verifier:Verifier|verifier-contract` — out of scope — stub verifier

Rejected candidates: 1 (kept in `findings.json` so a later run does not raise them again).

Companions not available: circom-auditor, solidity-auditor. Their areas were covered only by the embedded fallbacks.

Inventory load mode: `syntax` (1 load error). Items marked unresolved in `inventory.md` were not type-checked.

- go/packages: cannot find module providing package github.com/consensys/gnark/frontend

> This review is a time-boxed, best-effort search for bugs by an automated
> agent. It is not a guarantee of security. Absence of a finding is not
> evidence of absence of bugs.
