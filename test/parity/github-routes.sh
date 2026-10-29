#!/usr/bin/env bash
# Install zk-audit from GitHub both ways in a throwaway HOME.
# Usage: github-routes.sh <tmp-home> <branch>
set -uo pipefail
export HOME="$1"; branch="$2"
mkdir -p "$HOME"
C="${CLAUDE_BIN:-claude}"
echo "## plugin route: marketplace add shramee/zk-audit (default branch)"
$C plugin marketplace add shramee/zk-audit 2>&1 | tail -2
$C plugin install zk-audit@zk-audit 2>&1 | tail -1
$C plugin details zk-audit@zk-audit 2>&1 | sed -n '1p;/Component inventory/,/Agents/p'
echo "## prompt route: clone $branch and copy the skill folder"
tmp="$(mktemp -d)"
git clone -q --depth 1 -b "$branch" https://github.com/shramee/zk-audit "$tmp/zk-audit" 2>&1 | tail -1
mkdir -p "$HOME/.claude/skills" && rm -rf "$HOME/.claude/skills/zk-audit"
cp -R "$tmp/zk-audit/plugins/zk-audit/skills/zk-audit" "$HOME/.claude/skills/zk-audit"
ls "$HOME/.claude/skills/zk-audit"
ZK_AUDIT_BIN="$HOME/.zk-audit/bin" "$HOME/.claude/skills/zk-audit/scripts/gnark-inventory" version
echo "## update check against the published VERSION on main (expect silent)"
"$HOME/.claude/skills/zk-audit/scripts/check-version"; echo "exit=$?"
curl -sS -o /dev/null -w 'raw VERSION on main: HTTP %{http_code}\n' --max-time 5 https://raw.githubusercontent.com/shramee/zk-audit/main/plugins/zk-audit/skills/zk-audit/VERSION
curl -sS -o /dev/null -w "raw VERSION on $branch: HTTP %{http_code}\n" --max-time 5 "https://raw.githubusercontent.com/shramee/zk-audit/$branch/plugins/zk-audit/skills/zk-audit/VERSION"
