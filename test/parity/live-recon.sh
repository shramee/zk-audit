#!/usr/bin/env bash
# Live end-to-end: standalone skill install (throwaway HOME), headless
# "/zk-audit recon" on a sanitized fixture. Writes go to the throwaway HOME's
# ~/.zk-audit only. Usage: live-recon.sh <tmp-home> <target> <budget-usd> <model>
set -uo pipefail
export HOME="$1"; target="$2"; budget="$3"; model="${4:?model alias}"
export ZK_AUDIT_BIN="$HOME/.zk-audit/bin"
GOCACHE="$(go env GOCACHE)"; GOMODCACHE="$(go env GOMODCACHE)"; export GOCACHE GOMODCACHE
cd "$target" || exit 2
timeout 900 "${CLAUDE_BIN:-claude}" -p \
  --model "$model" --max-budget-usd "$budget" --no-session-persistence \
  --output-format json --add-dir "$HOME" \
  --allowed-tools "Skill,Read,Glob,Grep,Write,Bash(*/scripts/gnark-inventory *),Bash(*/scripts/check-version*),Bash(mkdir *),Bash(date *),Bash(ls *),Bash(go version*),Bash(git rev-parse *),Bash(basename *)" \
  <<<"/zk-audit recon" 2>&1 | head -c 60000
echo
