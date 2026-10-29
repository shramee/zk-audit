# Resume mode

Entry points: `/zk-audit:resume [run-id|out-dir] [--budget USD]` (plugin
install) or `/zk-audit resume [run-id|out-dir] [--budget USD]` (any
install). `{skill}` is the directory that holds the skill's `SKILL.md`. It
continues a full audit whose session ended (closed terminal, lost
container, budget raised) from its output directory, without redoing the
agents whose output is saved.

1. Find the run:
   `{skill}/scripts/gnark-inventory args --repo <repo> --save -- resume <arguments>`.
   With no argument it takes the latest run under `~/.zk-audit/<repo>/`
   that has a `run.json` and no `REPORT.md`; a run id or an output
   directory names one. It prints the original run (profile, scope, flags,
   `out`, `run_id`) with `resume: true`, and `--budget` replaces the saved
   ceiling. Exit 1: show the problems and stop. A run started before
   `run.json` existed cannot be resumed this way; say so.
2. Print the banner of `SKILL.md` §4 with `resumed run <run_id>`.
3. Read the state:
   `{skill}/scripts/gnark-inventory status --out <out>`. It prints each step
   as done, partial, todo or skipped, the planned agents saved, missing, to
   retry and blocked, the spend and any budget stop, and `Next`. Print the
   phase table of `SKILL.md` §4 with the done phases `Done`.
4. Continue at `Next`, then follow `SKILL.md` and
   `references/orchestration.md` from that step to the report:
   - Never respawn an agent the status lists as saved.
   - Spawn the missing agents; retry each agent listed under retry once,
     in plain words; record blocked agents and their units as blocked
     (the recovery rule in `references/orchestration.md`).
   - Run `budget check` before each wave as usual: the spend so far is in
     `<out>/spend.json`. If the status reports a budget stop, spawn nothing,
     close the ledger and assemble the partial report, unless the user
     raised `--budget`.
   - Judging restarts from the saved agent outputs in `<out>/agents/`:
     drafts that lived only in the old conversation are gone.
   - A scratch worktree left by the old session at `<out>/worktree` is
     reused when `git -C <out>/worktree status` works; otherwise run
     `git -C <repo> worktree prune` and add it again (hard rule 3).
5. Run `status` again before the report; it must say the only open steps
   are the report steps.
