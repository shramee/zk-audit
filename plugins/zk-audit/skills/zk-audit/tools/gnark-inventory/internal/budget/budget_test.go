package budget

import (
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/estimate"
)

func TestRecordAndTotals(t *testing.T) {
	out := t.TempDir()
	l, ok, err := Load(out)
	if err != nil || ok {
		t.Fatalf("empty dir: %v %v", ok, err)
	}
	l.Profile = "standard"
	for _, e := range []Entry{
		{ID: "C1", Tokens: 60000},
		{ID: "C2"}, // not reported: estimated
		{ID: "C2", Status: "refused"},
		{ID: "critic", Tokens: 100000},
		{ID: "poc-1", Role: "poc"},
	} {
		if err := l.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Record(Entry{ID: "x", Role: "nope"}); err == nil {
		t.Error("unknown role accepted")
	}
	if err := l.Save(out); err != nil {
		t.Fatal(err)
	}
	l, ok, err = Load(out)
	if err != nil || !ok {
		t.Fatal(err)
	}
	tot := l.Totals()
	c := estimate.Load()
	wantEst := 2*c.HunterTokens("standard", c.ReferenceSourceLines) + c.Roles.PoC
	if tot.Agents != 4 || tot.Attempts != 5 || tot.Reported != 160000 || tot.Estimated != wantEst {
		t.Errorf("totals: %+v (want estimated %d)", tot, wantEst)
	}
	if l.Entries[2].Attempt != 2 || l.Entries[3].Role != "critic" || l.Entries[1].Source != "estimated" {
		t.Errorf("entries: %+v", l.Entries)
	}
	if tot.USD <= 0 || tot.USDLow > tot.USD || tot.USDHigh < tot.USD {
		t.Errorf("usd: %+v", tot)
	}
	if s := l.Summary(); !strings.Contains(s, "reported") || !strings.Contains(s, "estimated") {
		t.Errorf("summary: %s", s)
	}
}

func TestCheckStopsBeforeTheCeiling(t *testing.T) {
	l := &Ledger{Profile: "quick"}
	d := l.Check("hunt pass 1", Wave{"hunter": 16}, 0)
	if d.Stop || !strings.Contains(d.Reason, "no budget") {
		t.Errorf("no budget: %+v", d)
	}
	l.BudgetUSD = 12
	d = l.Check("hunt pass 1", Wave{"hunter": 16}, 0)
	if d.Stop || d.NextUSD <= 0 || d.RemainingUSD != 12 {
		t.Fatalf("first wave fits: %+v", d)
	}
	for i := 0; i < 16; i++ {
		l.Record(Entry{ID: "V" + string(rune('a'+i)), Tokens: 49000})
	}
	d = l.Check("refuters", Wave{"refuter": 2}, 0)
	if d.Stop {
		t.Errorf("two refuters fit: %+v", d)
	}
	d = l.Check("targeted wave", Wave{"wave": 2, "critic": 1}, 0)
	if !d.Stop || l.Stopped == nil || l.Stopped.Before != "targeted wave" || d.Then == "" {
		t.Fatalf("over the ceiling: %+v %+v", d, l.Stopped)
	}
	// a stop is final
	if d = l.Check("report", Wave{}, 0); !d.Stop {
		t.Errorf("after a stop: %+v", d)
	}
	if len(l.Checks) != 5 {
		t.Errorf("checks recorded: %d", len(l.Checks))
	}
}

func TestRoleOf(t *testing.T) {
	for id, want := range map[string]string{"C1": "hunter", "C1@circuit/a": "hunter", "critic": "critic", "final-clean": "critic", "poc-2": "poc", "refuter-2": "refuter", "V-hints": "hunter"} {
		if got := RoleOf(id); got != want {
			t.Errorf("RoleOf(%s) = %s, want %s", id, got, want)
		}
	}
}
