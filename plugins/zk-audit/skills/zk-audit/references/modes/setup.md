# Setup mode

Entry points: `/zk-audit:setup [--check-only]` (plugin install) or
`/zk-audit setup [--check-only]` (any install, including a skill folder copied
into `~/.claude/skills/zk-audit`). `{skill}` is the directory that holds the
skill's `SKILL.md`.

1. Read `{skill}/references/companions.md`. It lists every tool and companion
   skill, how to detect it, and the install command to show.
2. Run each detection command. Do not install anything in this step.
3. Build the inventory tool if it is not built yet. It builds offline from the
   vendored sources in `{skill}/tools/gnark-inventory`:

   ```bash
   {skill}/scripts/gnark-inventory version
   ```

4. Run the update check (one GET of the public `VERSION` file; it prints a
   line only when a newer release exists, and nothing on any error):

   ```bash
   {skill}/scripts/check-version
   ```

5. Print one table: `component · status (✔ / ✖) · used for · install command`.
   Add a last row for zk-audit itself: `{skill}/VERSION`, the update-check
   line if any, and how it was installed (plugin: `{skill}` is under a
   `plugins/` cache directory, update with `/plugin marketplace update zk-audit` then
   `/plugin update zk-audit@zk-audit`;
   skill folder: `{skill}` is `~/.claude/skills/zk-audit` or a project
   `.claude/skills/zk-audit`, update by copying the folder from a fresh clone).
6. If the arguments contain `--check-only`, stop here.
7. For each missing component, ask the user with `AskUserQuestion` whether to
   run its install command. Run only the commands the user approves, one at a
   time, and show the output. If the runtime has no `AskUserQuestion`, stop
   after the table and tell the user to run the commands themselves.

Never edit the user's repository. Never install a companion skill by cloning it
into a plugin cache directory; use the command the table shows.
