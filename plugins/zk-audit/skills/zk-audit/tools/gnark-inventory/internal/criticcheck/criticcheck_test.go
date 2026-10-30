package criticcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/agents"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/ledger"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
)

func setup(t *testing.T) (string, *ledger.Ledger) {
	t.Helper()
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
	b, _ := json.Marshal(inv)
	os.WriteFile(filepath.Join(out, "inventory.json"), b, 0o644)
	l := ledger.Seed(inv, nil, "test")
	writeLedger(t, out, l)
	return out, l
}

func writeLedger(t *testing.T, out string, l *ledger.Ledger) {
	t.Helper()
	b, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(out, "coverage-ledger.json"), b, 0o644)
}

func find(r *Result, kind, prefix string) *Item {
	for i := range r.MissingUnits {
		if it := &r.MissingUnits[i]; it.Kind == kind && strings.HasPrefix(it.ID, prefix) {
			return it
		}
	}
	return nil
}

func TestCheckAndVerify(t *testing.T) {
	out, l := setup(t)
	// every unit is planned: listed once as open, not again as an item
	r, err := Check(out)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts["unit-open"] != len(l.Units) || r.Outputs != 0 {
		t.Errorf("open units: %v of %d", r.Counts, len(l.Units))
	}
	if find(r, "hint", "H1") != nil {
		t.Error("a hint whose unit is already open is listed twice")
	}
	// one hunter read the circuit and cited the first hint and a setter;
	// all units are marked covered by it
	if _, err := agents.Save(out, "C1", "FINDING | x\nlocation: circuit/transfer.go:61\nPool.setVerifier swaps the verifier\n", "done", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Mark(ledger.Selector{Status: "planned"}, ledger.Change{Status: "covered", Agents: []string{"C1"}}); err != nil {
		t.Fatal(err)
	}
	writeLedger(t, out, l)
	if r, err = Check(out); err != nil {
		t.Fatal(err)
	}
	if r.Counts["unit-open"] != 0 || r.Outputs != 1 {
		t.Errorf("counts after the hunt: %v", r.Counts)
	}
	if find(r, "hint", "H1 ") != nil {
		t.Error("H1 is cited at its line but listed")
	}
	h2 := find(r, "hint", "H2 ")
	if h2 == nil || h2.Lens != "C1" || h2.Unit == "" || h2.Source != "tool" {
		t.Fatalf("H2 is never cited: %+v", r.MissingUnits)
	}
	if find(r, "privileged", "Pool.setVerifier") != nil || find(r, "privileged", "Pool.addRoot") == nil {
		t.Errorf("privileged: %+v", r.MissingUnits)
	}
	// a unit marked covered by an agent with no output
	l.Units[0].AgentIDs = []string{"ghost"}
	writeLedger(t, out, l)
	if r, _ = Check(out); r.Counts["unit-no-output"] != 1 {
		t.Errorf("unit with no output: %v", r.Counts)
	}
	l.Units[0].AgentIDs = []string{"C1"}
	writeLedger(t, out, l)
	r, _ = Check(out)
	b, _ := json.Marshal(r)
	os.WriteFile(filepath.Join(out, File), b, 0o644)

	open, err := Undecided(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != len(r.MissingUnits) {
		t.Fatalf("no decision recorded yet: %d of %d open", len(open), len(r.MissingUnits))
	}
	// decisions: H2 deferred, addRoot run in the wave (its output now
	// names it), everything else dismissed with a note
	if _, err := l.Mark(ledger.Selector{IDs: []string{h2.Unit}}, ledger.Change{Status: "deferred", Reason: "critic-check: no time left"}); err != nil {
		t.Fatal(err)
	}
	if _, err := agents.Save(out, "T1", "LEAD | y\nPool.addRoot lets the owner post any root\n", "done", ""); err != nil {
		t.Fatal(err)
	}
	writeLedger(t, out, l)
	open, _ = Undecided(out)
	for _, it := range open {
		if it.ID == h2.ID || strings.HasPrefix(it.ID, "Pool.addRoot") {
			t.Errorf("decided item still open: %s", it.ID)
		}
	}
	for _, it := range open {
		if it.Unit != "" {
			l.Mark(ledger.Selector{IDs: []string{it.Unit}}, ledger.Change{Notes: "critic-check: dismissed, the shard is a test helper"})
		}
	}
	writeLedger(t, out, l)
	open, _ = Undecided(out)
	for _, it := range open {
		if it.Unit != "" {
			t.Errorf("dismissed item still open: %+v", it)
		}
	}
}
