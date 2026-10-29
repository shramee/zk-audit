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
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
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
	// the pool's verifier is gnark's: the custom-verifier shard is skipped
	for _, r := range res {
		if r.Agent == "V-custom" && (r.Status != "skipped" || !strings.Contains(r.Reason, "gnark did not generate")) {
			t.Errorf("V-custom on the pool: %+v", r)
		}
	}
	if b, _ := os.ReadFile(written["I1"].Path); !strings.Contains(string(b), "- entry point Pool.withdraw at `contracts/Pool.sol:") {
		t.Error("I1 bundle lacks the entry points of its shard")
	}
}

// TestBundlesCustomVerifier: a verifier gnark did not generate turns on the
// V-custom shard (its `when` condition), and the bundle lists the verifier
// with its generator and precompiles.
func TestBundlesCustomVerifier(t *testing.T) {
	root := fixture.Dir(t, "sol-library")
	r, err := solidity.ScanRepo(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{SchemaVersion: "1", Repo: root, Contracts: r}
	if !ConditionHolds("non-gnark-verifier", inv) || strings.Join(CustomVerifiers(inv), ",") != "Groth16Lib,HandVerifier" {
		t.Fatalf("custom verifiers: %v", CustomVerifiers(inv))
	}
	out := t.TempDir()
	b, _ := json.Marshal(inv)
	os.WriteFile(filepath.Join(out, "inventory.json"), b, 0o644)
	os.MkdirAll(filepath.Join(out, "regen"), 0o755)
	os.WriteFile(filepath.Join(out, "regen", "diff.json"), []byte(`{"sides":[{"name":"src/HandVerifier.sol"},{"name":"regen/output/Verifier.sol"}],"summary":"different structure and different verifying key"}`), 0o644)
	res, err := Build(Options{Out: out, Skill: filepath.Join("..", "..", "..", ".."), Profile: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, x := range res {
		if x.Agent == "V-custom" {
			path = x.Path
			if x.Status != "written" {
				t.Fatalf("V-custom: %+v", x)
			}
		}
	}
	md, _ := os.ReadFile(path)
	for _, want := range []string{"- verifier HandVerifier at `src/HandVerifier.sol:", "generator hand-written", "V-CV5. Public inputs not checked",
		"- regenerated verifier (verifier regen): `src/HandVerifier.sol` vs `regen/output/Verifier.sol`: different structure and different verifying key"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("V-custom bundle lacks %q", want)
		}
	}
	// a gateway call alone also turns it on
	gw := &inventory.Inventory{Contracts: &solidity.Result{VerifyCalls: []solidity.VerifyCall{{Contract: "App", Function: "run", ReceiverType: "ISP1Verifier"}}}}
	if !ConditionHolds("non-gnark-verifier", gw) {
		t.Error("an SP1 gateway call should route the custom-verifier shard")
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
