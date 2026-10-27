---
description: "Show which zk-audit companions and tools are present (go, gnark-inventory, forge, semgrep, slither, companion skills) and print the exact install command for each missing one. Installs nothing unless the user confirms each command."
argument-hint: "[--check-only]"
allowed-tools: Bash Read Glob AskUserQuestion
---

# zk-audit setup

Use the `zk-audit` skill's companion rules in
`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit/references/companions.md`.

1. Read `companions.md`. It lists every tool and companion skill, how to detect
   it, and the install command to show.
2. Run each detection command. Do not install anything in this step.
3. Build the inventory tool if it is not built yet. This is the only action
   that may download a module, and only `golang.org/x/tools` if the vendored
   copy is missing:

   ```bash
   ${CLAUDE_PLUGIN_ROOT}/scripts/gnark-inventory version
   ```

4. Print one table: `component · status (✔ / ✖) · used for · install command`.
5. If `$ARGUMENTS` contains `--check-only`, stop here.
6. For each missing component, ask the user with `AskUserQuestion` whether to
   run its install command. Run only the commands the user approves, one at a
   time, and show the output. If the runtime has no `AskUserQuestion`, stop
   after the table and tell the user to run the commands themselves.

Never edit the user's repository. Never install a companion skill by cloning it
into a plugin directory; use the `/plugin` command the table shows.
