#!/usr/bin/env bash
# Does the companions.md fallback detection find a symlinked skill (the way
# companions.md installs pashov / zkSecurity skills) and a plugin-cache skill?
set -u
P="$1"
rm -rf "$P"; mkdir -p "$P/src/x-ray" "$P/skills" "$P/plugins/cache/mkt/plug/1.0.0/skills/fp-check"
echo x > "$P/src/x-ray/SKILL.md"
echo x > "$P/plugins/cache/mkt/plug/1.0.0/skills/fp-check/SKILL.md"
ln -sfn "$P/src/x-ray" "$P/skills/x-ray"
echo "symlinked skill, current rule (find, maxdepth 6):"; find "$P/skills" -maxdepth 6 -name SKILL.md -path "*/x-ray/*"
echo "symlinked skill, find -L:"; find -L "$P/skills" -maxdepth 6 -name SKILL.md -path "*/x-ray/*"
echo "plugin-cache skill, current rule (maxdepth 6):"; find "$P/plugins" -maxdepth 6 -name SKILL.md -path "*/fp-check/*"
echo "plugin-cache skill, maxdepth 8:"; find -L "$P/plugins" -maxdepth 8 -name SKILL.md -path "*/fp-check/*"
