---
description: "Show which zk-audit companions and tools are present (go, gnark-inventory, forge, semgrep, slither, companion skills) and print the exact install command for each missing one. Installs nothing unless the user confirms each command."
argument-hint: "[--check-only]"
allowed-tools: Bash Read Glob AskUserQuestion
---

# zk-audit setup

Run the `zk-audit` skill in **setup** mode with the arguments `$ARGUMENTS`.
`{skill}` is `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`. Read
`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/references/modes/setup.md` and follow it.
The same mode runs from a standalone skill install as `/zk-audit setup`.
