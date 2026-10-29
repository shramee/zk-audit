# Run 1 — solidity-auditor

<!--RUN pass=1 of=2 stamp=20261029-120000 sha=abc1234 agents=12/12-->

Pass 1 of 2 · 2026-10-29 · `abc1234` · 12/12 agents returned.

## Findings

<!--F key=vault|redeem|recipient-not-bound conf=80 kind=FINDING agents=3-->

[80] **Payout recipient is not bound to the proof**

`Vault.redeem` · Confidence: 80

**Description**
The proof does not cover `to`, so a copied transaction pays the attacker.

**Fix**

```diff
- function redeem(uint256[8] calldata proof, uint256 tag, uint256 root, address payable to) external {
+ function redeem(uint256[8] calldata proof, uint256 tag, uint256 root) external {
```

<!--/F-->

## Leads

<!--F key=vault|setfee|unbounded-fee kind=LEAD agents=1-->

- **Relayer sets any fee** — `Vault.setFee` · NEW — Code smells: no upper bound, no event — The relayer can set a fee above the payout. Not verified: whether fee is read on any payout path.

<!--/F-->
