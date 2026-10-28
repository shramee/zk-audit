---
description: "Review a gnark / ZK verifier change set (a PR, branch or commit range) with zk-audit. Treats removed Assert* or range checks, changed public-input order or tags, gnark version bumps, regenerated verifier contracts and VK changes as high-risk triggers."
argument-hint: "<base>[..<head>]"
---

# zk-audit diff

Run the `zk-audit` skill in **diff** mode with the arguments `$ARGUMENTS`.
`{skill}` is `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`. Read
`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/references/modes/diff.md` and follow it.
The same mode runs from a standalone skill install as `/zk-audit diff`.
