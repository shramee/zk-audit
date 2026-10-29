# Run 2 — solidity-auditor

<!--RUN pass=2 of=2 stamp=20261029-120000 sha=abc1234 agents=11/12-->

Pass 2 of 2 · 2026-10-29 · `abc1234` · 11/12 agents returned — the periphery agent died.

## Findings

<!--F key=vault|redeem|recipient-not-bound conf=90 kind=FINDING agents=5-->

[90] **Payout recipient is not bound to the proof**

`Vault.redeem` · Confidence: 90

**Description**
The proof does not cover `to`, so anyone who copies a pending redeem changes `to` and takes the payout.

**Fix**

```diff
- uint256[2] memory pub;
+ uint256[3] memory pub;
+ pub[2] = uint256(uint160(address(to)));
```

<!--/F-->

<!--F key=router|swap|stale-price conf=60 kind=FINDING agents=1-->

[60] **Swap uses a stale price**

`Router.swap` · Confidence: 60

**Description**
The router reads a feed answer without checking `updatedAt`.

<!--/F-->

## Leads

<!--F key=basevault|_checkandspend|tag-not-reduced kind=LEAD agents=2-->

- **Tag is not reduced before it marks the spend** — `BaseVault._checkAndSpend` — Code smells: tag used as mapping key before the verifier call — If the verifier accepts tag + r, the same proof spends twice.

<!--/F-->
