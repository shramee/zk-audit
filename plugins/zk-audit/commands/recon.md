---
description: "Run zk-audit recon only on a gnark repository: stack detection, advisory check, circuit and public-witness inventory, hint and footgun inventory, draft public-input binding table and system map, plus threat-model questions. No hunting agents; cheap first step before a full audit."
argument-hint: "[path ...]"
---

# zk-audit recon

Run the `zk-audit` skill in **recon** mode with the arguments `$ARGUMENTS`.
`{skill}` is `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`. Read
`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/references/modes/recon.md` and follow it.
The same mode runs from a standalone skill install as `/zk-audit recon`.
