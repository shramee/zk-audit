package kblint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/advisory"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/inventory"
)

var skillDir = filepath.Join("..", "..", "..", "..", "skills", "zk-audit")

// TestKnowledgeBase lints the shipped knowledge base. Set GNARK_SRC to a gnark
// checkout to also verify every cited gnark/<path>.
func TestKnowledgeBase(t *testing.T) {
	rep, err := Lint(skillDir, inventory.RuleIDs(), Options{GnarkSrc: os.Getenv("GNARK_SRC")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Errors {
		t.Error(e)
	}
	if rep.Vectors < 60 || rep.Slices < 12 {
		t.Errorf("knowledge base too small: %d vectors in %d slices", rep.Vectors, rep.Slices)
	}
}

// TestVersionsInSync keeps gnark-versions.md's JSON block identical to the
// table embedded in the detect tool.
func TestVersionsInSync(t *testing.T) {
	md, err := os.ReadFile(filepath.Join(skillDir, "references", "gnark-versions.md"))
	if err != nil {
		t.Fatal(err)
	}
	block, err := VersionsBlock(md)
	if err != nil {
		t.Fatal(err)
	}
	same, err := SameJSON(block, advisory.Raw())
	if err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Fatal("gnark-versions.md JSON block differs from internal/advisory/advisories.json")
	}
	tab, err := advisory.Parse(block)
	if err != nil || len(tab.Advisories) == 0 {
		t.Fatalf("versions block does not parse as an advisory table: %v", err)
	}
}

func writeSkill(t *testing.T, slice string) string {
	t.Helper()
	dir := t.TempDir()
	refs := filepath.Join(dir, "references")
	if err := os.MkdirAll(filepath.Join(refs, "attack-vectors"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"SKILL.md":                           "---\nname: x\n---\nSee `references/poc-templates.md`.\n",
		"references/poc-templates.md":        "## T-GOOD\n",
		"references/gnark-versions.md":       "| GHSA |\n```json\n" + string(advisory.Raw()) + "```\n",
		"references/attack-vectors/index.md": "| `attack-vectors/a.md` | x | V-A1 | 1 |\n",
		"references/attack-vectors/a.md":     slice,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLintCatchesProblems(t *testing.T) {
	good := "**V-A1. Good**\n\n- **D:** d\n- **FP:** f\n- **Source:** https://github.com/Consensys/gnark/security/advisories/GHSA-498w-5j49-vqjg\n- **Seed:** FG-DIV-UNCHECKED\n- **PoC:** T-GOOD\n"
	// table rows in gnark-versions.md must name every advisory; the minimal
	// fixture does not, so only look for the vector errors here
	rep, err := Lint(writeSkill(t, good), inventory.RuleIDs())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Errors {
		if strings.Contains(e, "V-A1") || strings.Contains(e, "zero vectors") {
			t.Errorf("good vector flagged: %s", e)
		}
	}
	bad := "**V-A1. Bad**\n\n- **D:** d\n- **FP:** TODO\n- **Source:** https://evil.example.org/x\n- **Seed:** FG-NOPE\n- **PoC:** T-MISSING\n"
	rep, err = Lint(writeSkill(t, bad), inventory.RuleIDs())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Errors, "\n")
	for _, want := range []string{"placeholder", "not in the allowed list", "unknown inventory rule FG-NOPE", "unknown template T-MISSING"} {
		if !strings.Contains(joined, want) {
			t.Errorf("want %q in:\n%s", want, joined)
		}
	}
	noSource := "**V-A1. Bad**\n\n- **D:** d\n- **FP:** f\n- **Seed:** manual\n- **PoC:** T-GOOD\n"
	rep, _ = Lint(writeSkill(t, noSource), inventory.RuleIDs())
	if !strings.Contains(strings.Join(rep.Errors, "\n"), "missing or empty Source:") {
		t.Errorf("missing Source not caught: %v", rep.Errors)
	}
	rep, _ = Lint(writeSkill(t, "no vectors here\n"), inventory.RuleIDs())
	if !strings.Contains(strings.Join(rep.Errors, "\n"), "zero vectors inspected") {
		t.Errorf("zero vectors must fail: %v", rep.Errors)
	}
}
