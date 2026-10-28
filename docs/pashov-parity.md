# Parity with pashov/skills

Question from the owner: does zk-audit install and run the way
[pashov/skills](https://github.com/pashov/skills) does ("Install
https://github.com/pashov/skills/ and run x-ray"), and if not, what changes?

Short answer: **before this branch, no.** The Claude Code plugin route worked,
but a pashov-style copy of the skill folder into `~/.claude/skills/zk-audit`
lost the tool, the schemas and the agent briefs, and resolved `{plugin}` to
`~/.claude`. After this branch both routes run the same audit, and `make
check` (CI) proves the standalone copy on every push.

Reference read: pashov/skills at its `main` branch (shallow clone):
`README.md`, `CLAUDE.md`, `solidity-auditor/SKILL.md`, `x-ray/SKILL.md`,
`x-ray/references/templates.md`, `.github/workflows/version-bump.yml`. Tested
with the Claude Code CLI 2.1.312, every install in a throwaway `HOME` under
the session scratchpad; the real `~/.claude` was not touched.

## Verdict table

Status: **same**, **different by design**, **fixed here** (changed on
`feat/pashov-parity`), **missing** (not done; reason given).

| pashov feature | zk-audit status | Evidence / where |
|---|---|---|
| Prompt install: "Install `<repo url>` and run `<skill>`" in the README | **fixed here** | README "Install" now has the prompts and the exact clone + copy the agent should run, plus an "update to the latest version" prompt. |
| Self-contained skill folder (`SKILL.md` + `references/` + `scripts/` + `VERSION`, copied alone into `~/.claude/skills/<name>`) | **fixed here** | Before: [standalone copy, before](#b-standalone-skill-folder-pashov-route). `scripts/`, `schemas/`, `tools/gnark-inventory/` moved into `plugins/zk-audit/skills/zk-audit/`; agent briefs added under `skills/zk-audit/agents/`; setup/recon/diff procedures moved to `references/modes/`. |
| `$SKILL_DIR` = directory of the loaded `SKILL.md` | **fixed here** | `SKILL.md` defines `{skill}` with a fallback order (`${CLAUDE_PLUGIN_ROOT}/skills/zk-audit`, `~/.claude/skills/zk-audit`, `.claude/skills/zk-audit`). The old `{plugin} = {skill}/../..` pointed at `~/.claude` in a standalone copy, and `{plugin}/agents/` at the user's own agents directory. `TestSkillIsSelfContained` forbids `{plugin}` and `{skill}/..` in the skill folder and checks every `{skill}/<path>` exists. |
| `VERSION` file per skill | **fixed here** | `skills/zk-audit/VERSION` (`0.1.0`). `TestPluginMetadata` keeps it equal to `plugin.json` and the tool's `Version`. |
| Non-blocking version check (curl the published `VERSION`, warn only when local is lower, silent on failure) | **fixed here** | `skills/zk-audit/scripts/check-version` (3 s limit, numeric dotted compare, silent on equal / newer / offline / junk, `ZK_AUDIT_NO_UPDATE_CHECK=1` opt-out). `TestCheckVersionScript` covers each case with `file://` URLs. Run in Turn 1 and in setup mode; hard rule 8 names it as the one network exception. |
| CI bumps an integer `VERSION` on every push to `main` (`version-bump.yml`) | **different by design** | zk-audit uses semver shared by `plugin.json`, the marketplace entry, the tool and `VERSION`; a test keeps them equal. CI runs with `contents: read` and does not commit. |
| Banner printed first | **same (adjusted)** | Plain two-line text banner with the version, not ASCII art. It no longer prints a profile before the profile question is asked. |
| Progress tracking (`TodoWrite` phases, exactly one in progress) | **fixed here** | `SKILL.md` §4 now gives the exact phase table (`Pending → Running → Done/Skipped/Blocked`, one `Running`), mirrors it to `TodoWrite` where available; the `Agent Progress` table in `orchestration.md` uses the same words (`Queued` became `Pending`). |
| One `AskUserQuestion` before spawning (model, pass count) | **same** | One question: profile and model, default preselected; stated default on runtimes without the tool. |
| Agents as general-purpose subagents briefed by a prompt file | **fixed here** | Plugin installs get `zk-audit:poc-builder` / `zk-audit:refuter` agent types; a standalone copy briefs a general-purpose agent with `{skill}/agents/*.md`. The plugin `agents/` are byte-identical copies (`TestAgentBriefsInSync`, `make sync-agents`). Hunting lenses were already general-purpose agents reading bundles. |
| Parallel agents | **different by design** | pashov spawns all 12 at once in the background and never respawns; zk-audit runs a bounded pool of at most 6 with a live console, because shards can be many (one per circuit package). |
| Deterministic report assembly (`assemble.sh`) | **same** | `gnark-inventory assemble` (Go), which also validates and refuses invalid input. |
| Loop / memory mode across runs | **missing** | `--loop N` and `memory.json` are described in `orchestration.md` only; no tool support (M7 in `PLAN.md`). |
| Output written into the project (`x-ray/`, `.solidity-auditor/`) | **different by design** | zk-audit writes to `~/.zk-audit/<repo>/<run-id>/` and never into the target unless `--file-output`. |
| Multi-runtime claim (Cursor, Codex, Copilot, Windsurf) | **different by design** | Claude Code first; prompts are runtime-neutral and the skill folder now works without the plugin, but no other runtime was tested. |
| Marketplace / plugin manifest | **zk-audit only** | pashov ships folders only; zk-audit ships both a marketplace and a self-contained skill folder. |
| MIT `LICENSE` | **different by design** | zk-audit stays unlicensed; `NOTICE` keeps the upstream MIT attributions. `claude plugin validate` reports `LICENSE_MISSING` under the plugin-directory profile only (see below). |
| Install of companions by clone + symlink | **fixed here** (detection) | The companion fallback detection used `find -maxdepth 6` without `-L`: it missed every symlinked install (the way `companions.md` installs pashov and zkSecurity skills) and every plugin-cache skill (7 levels deep). Now `find -L … -maxdepth 8`, plus project `.claude/skills`. |

## What was run

### (a) Plugin route

```console
$ claude plugin validate .
Validating marketplace manifest: …/.claude-plugin/marketplace.json
√ Validation passed

$ claude plugin validate plugins/zk-audit
× Found 1 problem the plugin directory refuses a submission for:
  > LICENSE: License missing (LICENSE_MISSING) …
‼ Found 1 plugin directory warning:
  > .claude-plugin/plugin.json icon: No icon (ICON_MISSING) …
These plugin directory checks do not change the result below. …
√ Validation passed
```

`--strict` also passes. `LICENSE_MISSING` and `ICON_MISSING` matter only for a
submission to the public plugin directory (`--profile directory`); both are
deliberate for now. The README-install advice was addressed by adding the
install lines to `plugins/zk-audit/README.md`.

Install into a throwaway `HOME` (`test/parity/plugin-install.sh <repo> <tmp-home>`,
which exports `HOME` and runs the CLI):

```console
$ claude plugin marketplace add <repo>
√ Successfully added marketplace: zk-audit (declared in user settings)
$ claude plugin install zk-audit@zk-audit
√ Successfully installed plugin: zk-audit@zk-audit (scope: user)
$ claude plugin details zk-audit@zk-audit
Component inventory
  Skills (4)  diff, recon, setup, zk-audit
  Agents (2)  refuter, poc-builder
Projected token cost
  Always-on:   ~740 tok   added to every session
```

The tool built and ran from the installed plugin cache
(`…/plugins/cache/zk-audit/zk-audit/0.1.0/scripts/gnark-inventory version` →
`0.1.0`, then `detect` on the pool fixture). Same result after the
restructure (`…/0.1.0/skills/zk-audit/{SKILL.md,VERSION,agents,references,schemas,scripts,tools}`).

### (b) Standalone skill folder (pashov route)

`test/parity/skill-copy.sh <repo> <tmp-home>` copies only `plugins/zk-audit/skills/zk-audit`
to `<tmp-home>/.claude/skills/zk-audit` and checks the paths the skill uses.

Before (origin/main):

```text
## tree (top)
SKILL.md
references/
## {plugin}=skill/../.. resolves to
<tmp-home>/.claude
MISSING {plugin}/scripts/gnark-inventory
MISSING {plugin}/schemas/findings.schema.json
MISSING {plugin}/agents/poc-builder.md
MISSING {plugin}/agents/refuter.md
MISSING {plugin}/tools/gnark-inventory/main.go
```

Every Phase 0, 1, 2 and 6 command in `SKILL.md` would fail, `/zk-audit:setup`,
`recon` and `diff` did not exist (commands are plugin-only), and the agent
fallback in `orchestration.md` pointed at `~/.claude/agents/poc-builder.md`.

After:

```text
## tree (top)
SKILL.md  VERSION  agents/  references/  schemas/  scripts/  tools/
found   {skill}/scripts/gnark-inventory
found   {skill}/schemas/findings.schema.json
found   {skill}/agents/poc-builder.md
found   {skill}/agents/refuter.md
found   {skill}/tools/gnark-inventory/main.go
```

`test/standalone-skill.sh` (now part of `make check` and CI) repeats this with
the full deterministic pipeline from the copy:

```text
== the copy names no path outside itself
== build + version            0.1.0
== detect                     gnark v0.14.0 (advisories: 3) · groth16 · bn254 · solidity: yes · foundry: yes
== inventory                  load: syntax · circuits: 3 · … · ledger units: 39
== validate                   OK ledger … 39 items inspected / OK stack … 1 items inspected
== bundle / validate findings OK findings … 1 items inspected
== assemble                   wrote …/REPORT.md: 0 confirmed · … · ledger: 0 of 39 applicable units examined
== lint-kb                    OK: 79 vectors in 12 slices, 15 reference files checked
== update check (offline, must be silent)
standalone skill folder: OK
```

`claude plugin validate` does not apply to a bare skill folder ("No manifest
found"); validating the parent `.claude` directory passes but lists no
components, so discovery was checked live instead.

### (c) Companion detection

`test/parity/companion-detect.sh <dir>` builds a symlinked skill and a plugin-cache skill:

```text
symlinked skill, current rule (find, maxdepth 6):     (nothing)
symlinked skill, find -L:                              …/skills/x-ray/SKILL.md
plugin-cache skill, current rule (maxdepth 6):        (nothing)
plugin-cache skill, maxdepth 8:                        …/plugins/cache/mkt/plug/1.0.0/skills/fp-check/SKILL.md
```

### (d) Live smoke tests

Headless `claude -p` with the cheapest model alias, `--max-budget-usd`, a
throwaway `HOME` and an allow-list of tools (`test/parity/live-*.sh`; they
spend money and need `MODEL` set). Total spend about **$0.06**.

| Run | HOME | Result | Cost |
|---|---|---|---|
| "list skills / commands containing zk" | empty (control) | no `zk-audit` | $0.002 |
| same | standalone skill copy | `zk-audit` | $0.007 |
| same | plugin install | `zk-audit:diff`, `zk-audit:recon`, `zk-audit:setup`, `zk-audit:zk-audit` | $0.002 |
| "load zk-audit, resolve `{skill}`, `test -x {skill}/scripts/gnark-inventory`" | standalone | `SKILL=<tmp-home>/.claude/skills/zk-audit`, `TOOL_OK` (the `ls` was refused by the headless permission rules: path outside the working directory) | $0.007 |
| `/zk-audit recon` on a sanitized copy of the pool fixture | standalone | Ran detect + inventory from the copied skill, validated the ledger, printed the advisories, circuits, binding table (`?` kept), hint inventory, footguns and 9 threat-model questions; wrote `~/.zk-audit/target-pool/recon-run/{stack.json,inventory.json,inventory.md,binding-table.md,coverage-ledger.json}`; target `git status` clean | $0.028 |
| `/zk-audit:setup --check-only` | plugin install | `${CLAUDE_PLUGIN_ROOT}` expanded, `references/modes/setup.md` followed, tool built, update check silent, 20-row status table, no install | $0.006 |

Observations from the live runs, not fixed here:

- The recon run named its output directory `recon-run` instead of
  `YYYYMMDD-HHMMSS` (its `date` call was in a compound command the
  allow-list refused) and did not write `system-map.md`. Both are prompt-only
  rules; nothing checks them.
- For a local directory marketplace Claude Code reads the plugin from the
  source directory, so `${CLAUDE_PLUGIN_ROOT}` pointed at the checkout, not
  the cache copy. A GitHub marketplace install uses the cache.
- Both routes put the skill outside the audited repository, so a session
  that restricts Bash to the working directory prompts for every tool call
  under `{skill}` or `~/.zk-audit`. pashov skills have the same property.
- The plugin cache also receives `evals/` (answer keys) and the tool's
  `testdata/` (fixtures with `BUG:` comments). The standalone copy carries
  `testdata/` too. See the x-ray "worth investigating" list.

### Not verified

- Installing from GitHub (`/plugin marketplace add shramee/zk-audit` and the
  prompt install): the public raw URL of `VERSION` returns 404 from this
  environment (the repository is private or not yet at that name), so the
  update check was verified with `file://` URLs and against the live 404
  (silent, exit 0) only.
- Runtimes other than Claude Code.
- A full audit (Phases 2-6) through either route; only recon and setup ran
  live.
