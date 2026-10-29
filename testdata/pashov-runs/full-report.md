# 🔐 Security Review — sol-inherit

---

## Scope

|  |  |
| --- | --- |
| **Mode** | default |
| **Files reviewed** | `src/Vault.sol` · `src/BaseVault.sol` |
| **Confidence threshold (1-100)** | 75 |

---

## Findings

[90] **1. Payout recipient is not bound to the proof**

`Vault.redeem` · Confidence: 90

**Description**
The proof does not cover `to`, so anyone who copies a pending redeem changes `to` and takes the payout.

**Fix**

```diff
- uint256[2] memory pub;
+ uint256[3] memory pub;
```

---

[60] **2. Swap uses a stale price**

`Router.swap` · Confidence: 60

**Description**
The router reads a feed answer without checking `updatedAt`.

---

Findings List

| # | Confidence | Title |
|---|---|---|
| 1 | [90] | Payout recipient is not bound to the proof |
| | | **Below Confidence Threshold** |
| 2 | [60] | Swap uses a stale price |

---

## Leads

_Vulnerability trails with concrete code smells where the full exploit path could not be completed in one analysis pass. These are not false positives — they are high-signal leads for manual review. Not scored._

- **Relayer sets any fee** — `Vault.setFee` — Code smells: no upper bound, no event — The relayer can set a fee above the payout. Not verified: whether fee is read on any payout path.

---

> ⚠️ This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given.
