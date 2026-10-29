package ledger

import (
	"encoding/json"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

func TestSeedValidates(t *testing.T) {
	root := fixture.Dir(t, "pool")
	prog, err := load.Load(root, load.Options{SyntaxOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Build(prog, inventory.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := detect.Detect(root, "test")
	if err != nil {
		t.Fatal(err)
	}
	l := Seed(inv, st, "test")
	b, _ := json.Marshal(l)
	rep, err := validate.Document("ledger", b)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("seeded ledger invalid: %v", rep.Errors)
	}
	kinds := map[string]int{}
	for _, u := range l.Units {
		kinds[u.Kind]++
		if u.Status != "planned" {
			t.Errorf("seed status %s", u.Status)
		}
	}
	// 2 production circuits x 6 classes; 9 public-input groups (Fees is one
	// group of 2); 3 production hint sites; 1 verifier; 4 functions that
	// verify or write proof state (constructor, setVerifier, addRoot,
	// withdraw) x 3 classes, plus the 2 owner-gated setters (setVerifier,
	// addRoot) x trusted-party; 1 role (Pool.owner); 1 setup site
	// (cmd/setup); 1 prover file; 1 dependency
	want := map[string]int{"circuit": 12, "public-input": 9, "hint": 3, "verifier": 1, "contract-fn": 14, "role": 1, "setup": 1, "prover": 1, "dependency": 1}
	for k, v := range want {
		if kinds[k] != v {
			t.Errorf("kind %s: %d units, want %d (all %v)", k, kinds[k], v, kinds)
		}
	}
	ids := map[string]bool{}
	for _, u := range l.Units {
		ids[u.ID] = true
	}
	for _, id := range []string{"contract-fn:Pool.setVerifier|trusted-party", "contract-fn:Pool.addRoot|trusted-party", "role:Pool.owner|trusted-party", "setup:cmd/setup/main.go|trusted-party"} {
		if !ids[id] {
			t.Errorf("missing trusted-party unit %s", id)
		}
	}
	for _, u := range l.Units {
		if u.Kind == "public-input" && strings.Contains(u.ID, "Fees") && !strings.Contains(u.Notes, "2 leaves") {
			t.Errorf("Fees unit should record its 2 leaves: %+v", u)
		}
	}
}
