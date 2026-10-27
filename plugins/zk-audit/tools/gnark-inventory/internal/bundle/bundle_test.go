package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/report"
)

func TestBundles(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "pool"))
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
	res, err := Build(Options{Out: out, Skill: filepath.Join("..", "..", "..", "..", "skills", "zk-audit"), Profile: "quick"})
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
