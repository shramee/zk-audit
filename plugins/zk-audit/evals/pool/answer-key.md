# Answer key — pool fixture

Fixture: `plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/testdata/pool` (gnark
v0.14.0, Groth16, BN254, Foundry). Audits run on the sanitized copy made by
`evals/sanitize pool <scratch>`; nothing an audit reads may point here.

Line numbers refer to the **unsanitized** fixture. The sanitized copy drops the
`// BUG:` / `// OK:` comment lines, so its line numbers are lower; match by
code, not by line.

The fixture was planted for the inventory tool, so the `BUG:` comments do not
all describe exploitable bugs. The "real impact" column is the reviewed
ground truth; scoring uses it.

## Planted items

| Id | Location (unsanitized) | Planted as | Real impact | Expected result |
|---|---|---|---|---|
| P1 | `circuit/transfer.go:51-58` | Merkle path ignores `Index`; leaf position unbound | **Critical.** `Path[0]` is never tied to the spent note (`In`, `Secret`) or to `Index`, and the nullifier `MiMC(Secret, Index)` uses two free values. Any prover takes a public leaf and siblings, picks a fresh `Secret`, and withdraws up to 2^64−1 wei per proof, repeatedly. Non-leftmost honest leaves cannot be proven (completeness). PoC: `TestPoC_MerkleLeafUnbound`. | confirmed, critical or high |
| P2 | `circuit/transfer.go:60-67` | `divHint` remainder `res[1]` never constrained | Low/info. The free output is unused; the quotient is pinned by `q·Out = In`. PoC: `TestPoC_DivRemainderFree`. | confirmed low/info, or lead |
| P3 | `circuit/transfer.go:78-80` | `DivUnchecked` 0/0 leaves `ratio` free | Info. `ratio` is unused; also `Fees[1] = 0, Fees[0] ≠ 0` is unprovable (completeness, no protocol effect). | lead, low/info, or hardening |
| P4 | `circuit/transfer.go:82-83` | `ToBinary(Out.Owner, OmitModulusCheck)` | Info. The bits are discarded, so the alias changes nothing. | lead, info, or hardening |
| P5 | `circuit/transfer.go:85-87` | "change wraps when Out.Value > In.Value" | **Decoy.** `In.Value < 2^64` (32-bit limbs at lines 70-76), so a wrapped `change` exceeds it and `AssertIsLessOrEqual` rejects. PoC: `TestDecoy_ChangeWrapRejected`. | not confirmed (rejected or absent); a confirmed item is a false positive |
| P6 | `circuit/transfer.go:89-91` | owner check holds trivially when `flag = 0` | Medium as written (owner equality is switched off for `Index ≠ 0`); no extra on-chain impact beyond P1 because `In.Owner` is unbound anyway. PoC: `TestPoC_OwnerCheckGated`. | confirmed (any severity) or lead |
| P7 | `circuit/transfer.go:93-94` | `api.IsZero(Recipient)` result dropped | Low/info. The intended non-zero check is missing (recipient 0 burns the caller's own funds). `Recipient` still appears in constraints, so Groth16 binds it; front-running a recipient change is **not** possible. | lead, low/info, or hardening; claiming recipient front-running is a false positive |
| P8 | `circuit/transfer.go:96-99` | Go `if` on a witness value | Info. Runs at compile time; no constraint is skipped for the shipped shape. | lead/info/hardening |
| P9 | `circuit/transfer.go:106-113` | `decompose` returns unconstrained hint outputs | Info. Dead code. | hardening or lead |
| P10 | `circuit/sig.go:38-39` | emulated `sq.Limbs[0]` used directly | Low/info. `Limbs[0] ≠ 0` is not `sq ≠ 0` for a non-canonical result; the check has no protocol use. | lead or low/info |
| P11 | `cmd/setup/main.go:21-22` | single-party `groth16.Setup` outside tests | High if these keys are deployed: whoever ran it can forge proofs. Depends on deployment. | needs_validation (high) or confirmed with the trust assumption named |
| P12 | `go.mod` | gnark v0.14.0 | GHSA-3mvx-pp85-pm65 (emulated arithmetic is used by `SigCircuit`), GHSA-7fx8 and GHSA-fwf3 (components unused). | reported from Phase 0 (needs_validation or confirmed, any severity) |
| P13 | `contracts/Pool.sol:20-23` | owner can swap the verifier | Trusted-party: the owner can accept any proof. | lead or needs_validation |
| P14 | `contracts/Pool.sol:25-28` | roots are set by the owner, not derived from deposits | Trusted-party: the owner can add a root of a fake tree and mint. | lead or needs_validation |
| P15 | `contracts/Pool.sol:30-53` | no chain id / contract address in the statement | Medium: a proof replays on a second deployment that shares the verifier and a root. | lead, needs_validation or confirmed medium |

## Other true observations (not planted, not scored as misses)

- `Pool` pays `value` = `Out.Value`; the change `In.Value − Out.Value` and the
  `Out` note are never stored, so change is lost. `fee0`/`fee1` and `ownerKey`
  are public inputs the contract never uses.
- `Pool` has no deposit or payable function.
- `contracts/Verifier.sol` is a placeholder that always reverts; it does not
  match what `cmd/setup` exports (VK drift / out of scope).

## Decoys (a confirmed item here is a false positive)

| Id | Pattern | Why it is safe |
|---|---|---|
| D1 | public inputs ≥ r aliasing nullifiers | `Verifier.verifyProof` reverts with `PublicInputNotInField`. |
| D2 | reentrancy around `verifyProof` | the call is `view` (staticcall); the nullifier is stored before `transfer`. |
| D3 | = P5 change wrap | see P5. |
| D4 | front-running by changing `recipient` | see P7; `TestPoC_MerkleLeafUnbound` checks that a proof fails to verify with a swapped recipient. |
| D5 | `eddsa.Verify` signature malleability | safe pattern on v0.14.0 (`judging.md` §7). |

## Scoring

- **Found**: a P-item matched by a record whose location overlaps the planted
  code and whose description names the same defect, with the expected
  verdict class. A lead for an item whose expected result is "confirmed"
  counts as **partial**.
- **Missed**: no record, lead or hardening note for the item. A mention in
  the posture text only does not count.
- **False positive**: a `confirmed` or `needs_validation` record with no
  matching P-item or "other true observation", or matching a decoy.
- Recall = (found + 0.5·partial) / 14, over P1–P15 without the decoy P5.
  Decoys D1–D5 are scored separately (handled = not confirmed). Report
  critical recall (P1) separately.
- PoC coverage (M4): confirmed circuit findings matched to P1, P2 or P6 have
  a working eval PoC in `pocs/poc_test.go`; `evals/run-pocs pool <scratch>`
  runs them.
