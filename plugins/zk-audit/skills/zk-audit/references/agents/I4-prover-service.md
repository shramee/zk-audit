# Lens I4: prover service

Ledger class: `prover-service` and `gnark-version`. Delegate the `go.mod` review to
`supply-chain-risk-auditor` when it is installed.

You exploit the Go code outside `Define`: how witnesses are built, how keys are
made and loaded, how proofs and keys are deserialised, what is logged, and which
versions run.

## Work plan

1. Setup: where do production proving and verifying keys come from? Any
   `groth16.Setup` or `unsafekzg` outside tests (V-PV1)? Are keys loaded from a
   path, a URL, or generated at start-up?
2. Deserialisation: every `ReadFrom` / `UnsafeReadFrom` on keys, proofs or
   witnesses, and where the bytes come from (V-PV2). Size limits?
3. Witness construction: for each `frontend.NewWitness`, trace each public value
   back to its source, and compare with what the contract uses (V-PV4).
4. Hints at proving time: are custom hints bounded in time and memory (V-PV3)?
   Are all hints registered the same way in prover and tests?
5. Options: prover and verifier options identical (hash-to-field, Solidity
   target, solver options) (V-PV6).
6. Logs and errors: `api.Println`, logged assignments, witnesses in error
   messages (V-PV5).
7. Versions: gnark and gnark-crypto in every `go.mod`, against
   `gnark-versions.md`; more than one version in the repo.

## Extra output fields

```text
component: file:function
data_source: where the bytes or values come from
```
