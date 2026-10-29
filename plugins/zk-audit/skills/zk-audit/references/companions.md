# Companions and tools

zk-audit delegates to companion skills when they are installed and falls back
to its own minimum when they are not. **It never installs anything without the
user's explicit yes.** `/zk-audit setup` (or `/zk-audit:setup`) shows this table with live status and
offers each install command; Phase 0 prints one status line.

## Detecting a companion skill

A companion is available when the runtime lists a skill with that name
(Claude Code: the skill appears in the available-skills list, possibly
namespaced as `<plugin>:<skill>`). As a fallback, check the usual locations:

```bash
for d in ~/.claude/skills .claude/skills ~/.claude/plugins ~/.agents/skills ~/.codex/skills; do
  [ -d "$d" ] && find -L "$d" -maxdepth 8 -name SKILL.md -path "*/<skill-name>/*" 2>/dev/null
done; true   # a missing directory is not a failure
```

`-L` follows the symlinks the install commands below create, and depth 8
reaches plugin caches (`~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/skills/<skill>/SKILL.md`
is seven levels down).

Report each as `✔ <name>` or `✖ <name> (install: …)`.

## Companion skills

| Skill | Source | Used for | Fallback | Install (show, ask, then run) |
|---|---|---|---|---|
| `circom-auditor` | zkSecurity zk-skills | `.circom` files in scope | `attack-vectors/generic-zk.md` | `git clone https://github.com/zksecurity/zk-skills.git ~/zk-skills && mkdir -p ~/.claude/skills && ln -sfn ~/zk-skills/skills/circom-auditor ~/.claude/skills/circom-auditor` |
| `solidity-auditor`, `x-ray` | pashov skills | Solidity beyond the ZK integration; threat model | I1–I3 cover the integration surface only; the report says so | `git clone https://github.com/pashov/skills.git ~/pashov-skills && mkdir -p ~/.claude/skills && ln -sfn ~/pashov-skills/solidity-auditor ~/.claude/skills/solidity-auditor && ln -sfn ~/pashov-skills/x-ray ~/.claude/skills/x-ray` |
| `audit-context-building` | Trail of Bits skills | deep profile: per-function dossiers | Phase 1 recon | `/plugin marketplace add trailofbits/skills` then `/plugin install audit-context-building@trailofbits` |
| `spec-to-code-compliance` | Trail of Bits skills | circuit vs spec / paper | C6 lens | `/plugin install spec-to-code-compliance@trailofbits` |
| `fp-check` | Trail of Bits skills | Phase 4 refuter | `zk-audit:refuter` with the prompt in `judging.md` | `/plugin install fp-check@trailofbits` |
| `vulnerability-triage-brocards` | Trail of Bits skills | first-pass filter before Phase 4 | `rationalizations.md` | `/plugin install vulnerability-triage-brocards@trailofbits` |
| `variant-analysis` | Trail of Bits skills | variants of a confirmed finding | grep `inventory.json` for the same rule id or shape | `/plugin install variant-analysis@trailofbits` |
| `static-analysis` | Trail of Bits skills | Semgrep / CodeQL on Go and Solidity | skip; note it under coverage | `/plugin install static-analysis@trailofbits` |
| `building-secure-contracts` | Trail of Bits skills | Slither on verifier callers | skip; note it under coverage | `/plugin install building-secure-contracts@trailofbits` |
| `supply-chain-risk-auditor` | Trail of Bits skills | `go.mod` dependency risk | `gnark-versions.md` | `/plugin install supply-chain-risk-auditor@trailofbits` |
| `differential-review` | Trail of Bits skills | PR review | `/zk-audit diff` | `/plugin install differential-review@trailofbits` |
| `property-based-testing`, `mutation-testing` | Trail of Bits skills | deep profile: oracle tests (native Go == circuit), constraint-deletion mutants | suggested tests in the report | `/plugin install property-based-testing@trailofbits` |

zk-audit only **names** Trail of Bits skills and calls them when installed. It
contains none of their text (they are CC BY-SA 4.0).

Delegated results come back as records in zk-audit's `findings.json` schema,
with `detected_by: <companion>`, so dedup and the report treat them like any
other agent.

## Tools

| Tool | Detect | Used for | Without it |
|---|---|---|---|
| Go ≥ 1.24 | `go version` | building `gnark-inventory`; running circuit PoCs | no inventory and no PoCs: guidance mode or `--local` manual review only |
| gnark-inventory | `{skill}/scripts/gnark-inventory version` | Phase 0 and 1 | as above |
| Foundry | `forge --version` | contract PoCs (T-FOUNDRY-*) | contract findings get `evidence: ANALYSIS` |
| Semgrep | `semgrep --version` | optional rules, `static-analysis` companion | skipped |
| Slither | `slither --version` | `building-secure-contracts` companion | skipped |
| git | `git --version` | scratch worktrees for PoCs and diff mode | PoCs disabled (`--no-poc` implied) |

Install commands to **show** (never run without consent): Go from
https://go.dev/dl/, Foundry with `curl -L https://foundry.paradigm.xyz | bash && foundryup`,
Semgrep with `python3 -m pip install semgrep`, Slither with
`python3 -m pip install slither-analyzer`.

## zkao (optional, paid)

zkSecurity's closed engine has a CLI (`@zksecurity/zkao-cli`). It is a second
opinion that needs an account and sends code to a third party. Offer it only
in deep profile, only as a suggestion, and never run it without explicit consent
and a user-provided token.
