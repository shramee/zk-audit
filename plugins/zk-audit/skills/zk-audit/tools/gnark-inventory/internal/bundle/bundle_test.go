package bundle

import (
	"bytes"
	"encoding/json"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/memory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/report"
)

func TestBundles(t *testing.T) {
	root := fixture.Dir(t, "pool")
	prog, err := load.Load(root, load.Options{SyntaxOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Build(prog, inventory.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(inv); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(out, "inventory.json"), buf.Bytes(), 0o644)
	os.WriteFile(filepath.Join(out, "binding-table.md"), []byte(report.BindingTable(inv)), 0o644)
	res, err := Build(Options{Out: out, Skill: filepath.Join("..", "..", "..", ".."), Profile: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	written := map[string]Result{}
	for _, r := range res {
		if r.Status == "written" {
			written[r.Agent] = r
		}
	}
	for _, id := range []string{"C1", "I1", "G2", "V-hints", "V-pubin", "V-prover"} {
		if _, ok := written[id]; !ok {
			t.Errorf("quick profile should write %s (got %v)", id, written)
		}
	}
	if _, ok := written["C2"]; ok {
		t.Error("C2 is not part of the quick profile")
	}
	b, _ := os.ReadFile(written["C1"].Path)
	s := string(b)
	if strings.Contains(s, "Already known") {
		t.Error("no memory.json, but an Already known section")
	}
	// loop mode: a merged pass makes later bundles inline the known list
	if _, err := memory.Init(out, 2); err != nil {
		t.Fatal(err)
	}
	pass := `{"schema_version":"1","repo":"pool","run_id":"20261029-101010","profile":"deep","records":[{"fingerprint":"Vote|tally|hint-output-unconstrained","verdict":"lead","title":"t","layer":"circuit","bug_class":"x","location":{"file":"c.go","line":3,"scope":"S"},"detected_by":["C1"],"description":"d","code_smells":["s"],"unverified":"u"}]}`
	if _, err := memory.Merge(out, 1, []byte(pass), 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Out: out, Skill: filepath.Join("..", "..", "..", ".."), Profile: "quick"}); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(written["C1"].Path); !strings.Contains(string(b2), "## 6a. Already known (loop memory)") || !strings.Contains(string(b2), "Vote|tally|hint-output-unconstrained") {
		t.Error("the known list is not inlined after a merged pass")
	}
	for _, want := range []string{"`circuit/transfer.go` | 113", "hint H1", "#### 1. Feynman", "## 7. Shared rules", "Lens C1: hint soundness"} {
		if !strings.Contains(s, want) {
			t.Errorf("C1 bundle lacks %q", want)
		}
	}
	if strings.Contains(s, "func (c *TransferCircuit) Define") {
		t.Error("bundles must list source files, not inline them")
	}
	if written["I1"].Files != 4 {
		t.Errorf("integration shard: %d files, want 2 contracts + 2 circuit decl files", written["I1"].Files)
	}
}

// TestPeripheralStdPath: hunters have no shell, so the bundle names the gnark
// std directory as an absolute path, or says it is not available.
func TestPeripheralStdPath(t *testing.T) {
	out := t.TempDir()
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	os.WriteFile(filepath.Join(out, "stack.json"), []byte(`{"gnark":{"versions":["v0.14.0","v0.9.9"]}}`), 0o644)
	std := filepath.Join(cache, "github.com", "consensys", "gnark@v0.14.0", "std")
	os.MkdirAll(std, 0o755)
	got := peripheral(out)
	if !strings.Contains(got, "`"+std+"`") {
		t.Errorf("present std not named: %s", got)
	}
	if !strings.Contains(got, "v0.9.9 is **not available**") {
		t.Errorf("missing std not flagged: %s", got)
	}
	if got := peripheral(t.TempDir()); !strings.Contains(got, "version unknown") {
		t.Errorf("no stack.json: %s", got)
	}
}
