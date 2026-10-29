#!/usr/bin/env bash
# Pashov-style install check: copies ONLY the skill folder into
# <throwaway HOME>/.claude/skills/zk-audit and runs the deterministic pipeline
# from that copy (build, detect, inventory, validate, bundle, assemble,
# lint-kb). Fails if the copy needs anything outside itself. Offline: the tool
# builds from its vendored sources and the update check is turned off.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Keep the caller's Go caches; only the install location changes.
GOCACHE="$(go env GOCACHE)"
GOMODCACHE="$(go env GOMODCACHE)"
export GOCACHE GOMODCACHE
export HOME="$work/home" ZK_AUDIT_BIN="$work/bin" ZK_AUDIT_NO_UPDATE_CHECK=1

skill="$HOME/.claude/skills/zk-audit"
mkdir -p "$HOME/.claude/skills"
cp -R "$root/plugins/zk-audit/skills/zk-audit" "$skill"

step() { printf '== %s\n' "$*"; }

step "the copy names no path outside itself"
if grep -RnE '\{plugin\}|\{skill\}/\.\.' --include='*.md' "$skill" | grep -v '/tools/'; then
  echo "standalone-skill: the skill folder refers outside itself (lines above)" >&2
  exit 1
fi
for f in SKILL.md VERSION agents/poc-builder.md agents/refuter.md agents/hunter.md agents/critic.md references/modes/setup.md \
  references/modes/recon.md references/modes/diff.md schemas/findings.schema.json \
  scripts/check-version; do
  [ -e "$skill/$f" ] || { echo "standalone-skill: missing $f in the copy" >&2; exit 1; }
done

gi="$skill/scripts/gnark-inventory"
fixture="$root/testdata/pool"
out="$work/out"
mkdir -p "$out"

step "build + version";   "$gi" version
step "detect";            "$gi" detect --repo "$fixture" --out "$out/stack.json"
step "inventory";         "$gi" inventory --repo "$fixture" --out "$out" --syntax-only
step "validate";          "$skill/scripts/validate-ledger" "$out/coverage-ledger.json"
                          "$gi" validate stack "$out/stack.json"
step "bundle";            "$gi" bundle --out "$out" --skill "$skill" --profile quick >/dev/null
ls "$out/bundles" | grep -q '^C1.*\.md$' || { echo "standalone-skill: no C1 bundle" >&2; exit 1; }
printf '%s\n' '{"schema_version":"1","repo":"pool","run_id":"20261028-000000","profile":"quick","no_findings":true,"no_findings_reason":"standalone install smoke test","records":[]}' >"$out/findings.json"
"$skill/scripts/validate-findings" "$out/findings.json"
step "assemble";          "$skill/scripts/assemble" --out "$out" --repo "$fixture" | tail -1
[ -s "$out/REPORT.md" ] || { echo "standalone-skill: no REPORT.md" >&2; exit 1; }
step "lint-kb";           "$gi" lint-kb "$skill"
step "update check (offline, must be silent)"
[ -z "$("$skill/scripts/check-version")" ]
echo "standalone skill folder: OK"
