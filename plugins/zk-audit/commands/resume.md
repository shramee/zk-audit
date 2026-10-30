---
description: "Continue an interrupted zk-audit run from its output directory: reads run.json and the saved agent outputs, reports which steps are done, and restarts at the first incomplete step without respawning agents whose output is saved. Optional run id or output directory; --budget USD raises the ceiling."
argument-hint: "[run-id|out-dir] [--budget USD]"
---

# zk-audit resume

Run the `zk-audit` skill in **resume** mode with the arguments `$ARGUMENTS`.
`{skill}` is `${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`. Read
`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/references/modes/resume.md` and follow it.
The same mode runs from a standalone skill install as `/zk-audit resume`.
