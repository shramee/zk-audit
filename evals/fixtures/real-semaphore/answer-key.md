# Answer key — real-semaphore (worldcoin/semaphore-mtb)

Real repository, **not vendored**. The case scaffold fetches
`github.com/worldcoin/semaphore-mtb` (module `worldcoin/gnark-mbu`) through the
Go module proxy, cached under `.cache/`. The pinned commit pins **gnark v0.8.0**.

## Scope and honesty note

semaphore-mtb has been reviewed publicly (Worldcoin's prover was covered by
third-party reviews), but **this snapshot ships no audit report**, and the
build environment here cannot reach github.com or the external report PDFs to
recover the exact findings and their fix commits. Rather than invent
circuit-level ground truth, this key scores **only the verifiable dependency
fact**:

| Id | Source | Expected |
|---|---|---|
| R1 | `go.mod` pins gnark v0.8.0, which is `< v0.9.0` (GHSA-498w-5j49-vqjg / CVE-2023-44378 full-width comparison), `< v0.9.2` (GHSA-rjjm rangecheck) and predates the commitment/eddsa fixes. Phase 0 must report it and recommend upgrading. | needs_validation / confirmed |

A real soundness audit of this repo's batch Merkle-tree circuits is possible
but is **not** scored here, because no reliable public answer key could be
established from this environment. Treat circuit-level findings on this case as
unscored observations, not as recall hits or misses. To key them, obtain the
public review for the pinned commit and add items with reviewed anchors.
