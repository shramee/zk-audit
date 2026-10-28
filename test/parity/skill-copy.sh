#!/usr/bin/env bash
# Pashov-style install: copy only the skill folder into <tmp-home>/.claude/skills/zk-audit
# and see what Claude Code discovers and which referenced paths resolve.
# Usage: skill-copy.sh <repo> <tmp-home>
set -uo pipefail
repo="$1"
export HOME="$2"
mkdir -p "$HOME/.claude/skills"
rm -rf "$HOME/.claude/skills/zk-audit"
cp -R "$repo/plugins/zk-audit/skills/zk-audit" "$HOME/.claude/skills/zk-audit"
C="${CLAUDE_BIN:-claude}"
skill="$HOME/.claude/skills/zk-audit"
echo "## tree (top)"; ls -F "$skill"
echo "## plugin list"; $C plugin list 2>&1 | tail -10
echo "## details zk-audit@skills-dir"; $C plugin details zk-audit@skills-dir 2>&1 | head -30
echo "## validate skill dir"; $C plugin validate "$skill" 2>&1 | tail -8
echo "## {plugin}=skill/../.. resolves to"; (cd "$skill/../.." && pwd)
for p in scripts/gnark-inventory schemas/findings.schema.json agents/poc-builder.md agents/refuter.md tools/gnark-inventory/main.go .claude-plugin/plugin.json; do
  if [ -e "$skill/../../$p" ]; then echo "found   {plugin}/$p"; else echo "MISSING {plugin}/$p"; fi
  if [ -e "$skill/$p" ]; then echo "found   {skill}/$p"; else echo "MISSING {skill}/$p"; fi
done
