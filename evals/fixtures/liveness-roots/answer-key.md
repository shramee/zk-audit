# Answer key — liveness-roots fixture

Fixture: `testdata/liveness-roots` (Foundry, no gnark). A fixed-denomination
pool that keeps the last 8 Merkle roots in a ring buffer. Audits run on the
sanitized copy made by `evals/sanitize liveness-roots <scratch>`.

| Id | Location | Real impact | Expected result |
|---|---|---|---|
| L1 | `src/RootRing.sol` `ROOT_HISTORY`, `deposit`, `withdraw` | **Low to medium (liveness).** Every deposit pushes a root; after 8 more deposits a pending withdrawal's root is gone and its valid proof reverts with `unknown root`. Anyone who sees the withdrawal in the mempool front-runs it with 8 deposits and withdraws them again afterwards, so the griefing costs gas only and can repeat. The victim re-proves against a newer root, so funds are delayed, not lost. PoC: `pocs/StaleRoot.t.sol` (`test_attack_frontRunEvictsPendingRoot`, with honest control and window-minus-one sanity). | confirmed or needs_validation, low or medium |

The verifier is a mock in the PoC on purpose: the bug is in the root window,
not in the proof system. The recipient is a public input, so front-running
cannot redirect the payout.
