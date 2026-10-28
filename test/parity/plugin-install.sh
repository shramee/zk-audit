#!/usr/bin/env bash
# Install the zk-audit marketplace + plugin from a local checkout into a
# throwaway HOME and list what Claude Code discovers.
# Usage: plugin-install.sh <repo> <tmp-home>
set -uo pipefail
repo="$1"
export HOME="$2"
mkdir -p "$HOME"
C="${CLAUDE_BIN:-claude}"
echo "## marketplace add"; $C plugin marketplace add "$repo" 2>&1 | tail -5
echo "## marketplace list"; $C plugin marketplace list 2>&1 | tail -8
echo "## install"; $C plugin install zk-audit@zk-audit 2>&1 | tail -5
echo "## list"; $C plugin list 2>&1 | tail -10
echo "## details"; $C plugin details zk-audit@zk-audit 2>&1 | head -60
echo "## installed tree"; find "$HOME/.claude/plugins" -maxdepth 6 -name '*.md' -path '*zk-audit*' 2>/dev/null | grep -v references | head -20
