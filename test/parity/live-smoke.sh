#!/usr/bin/env bash
# Live smoke test (spends money; set MODEL): ask a headless claude, with a throwaway HOME, which skills
# it can see. Usage: live-smoke.sh <tmp-home> <workdir> <budget-usd> [extra claude args...]
set -uo pipefail
export HOME="$1"; work="$2"; budget="$3"; shift 3
cd "$work" || exit 2
timeout 240 "${CLAUDE_BIN:-claude}" -p \
  --model "${MODEL:?set MODEL to a cheap model alias}" --max-budget-usd "$budget" --no-session-persistence \
  --output-format json --permission-mode default --disallowed-tools Bash Write Edit \
  "$@" <<<"Without using any tools, list the names of every skill and slash command available to you whose name contains 'zk'. One per line, names only. If none, reply NONE." 2>&1 | head -c 4000
echo
echo "exit=$?"
