#!/usr/bin/env bash
# Live check of a mode through an install route.
# Usage: live-setup.sh <tmp-home> <workdir> <budget-usd> <prompt>
set -uo pipefail
export HOME="$1"; work="$2"; budget="$3"; prompt="$4"
export ZK_AUDIT_BIN="$HOME/.zk-audit/bin"
GOCACHE="$(go env GOCACHE)"; GOMODCACHE="$(go env GOMODCACHE)"; export GOCACHE GOMODCACHE
cd "$work" || exit 2
timeout 600 "${CLAUDE_BIN:-claude}" -p \
  --model "${MODEL:?set MODEL to a cheap model alias}" --max-budget-usd "$budget" --no-session-persistence \
  --output-format json --add-dir "$HOME" \
  --allowed-tools "Skill,Read,Glob,Grep,Bash(*/scripts/gnark-inventory *),Bash(*/scripts/check-version*),Bash(go version*),Bash(forge --version*),Bash(semgrep --version*),Bash(slither --version*),Bash(git --version*),Bash(command -v *),Bash(find *),Bash(ls *)" \
  <<<"$prompt" 2>&1 | head -c 60000
echo
