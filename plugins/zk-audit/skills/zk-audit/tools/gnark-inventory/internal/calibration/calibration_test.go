package calibration

import (
	"strings"
	"testing"
)

func TestEmbeddedTable(t *testing.T) {
	tab := Load()
	if len(tab.Anchors) < 15 || len(tab.Examples) < 30 {
		t.Fatalf("calibration table too small: %d anchors, %d examples", len(tab.Anchors), len(tab.Examples))
	}
	// the anchors the 2026-10-29 runs needed (shramee/zk-audit#10)
	for id, want := range map[string]struct{ verdict, ok, bad string }{
		"SC-UNUSED-FREE-VALUE":  {"confirmed", "info", "medium"},
		"SC-MASKED-BYPASS":      {"confirmed", "low", "medium"},
		"SC-TRUST-SOUNDNESS":    {"needs_validation", "high", "low"},
		"SC-SETUP-SINGLE-PARTY": {"needs_validation", "high", "medium"},
	} {
		a, ok := tab.Anchor(id)
		if !ok {
			t.Fatalf("missing anchor %s", id)
		}
		if msg := a.Check(want.verdict, want.ok); msg != "" {
			t.Errorf("%s: %s %s refused: %s", id, want.verdict, want.ok, msg)
		}
		if msg := a.Check(want.verdict, want.bad); !strings.Contains(msg, "severity") {
			t.Errorf("%s: %s %s accepted", id, want.verdict, want.bad)
		}
	}
	a, _ := tab.Anchor("SC-TRUST-SOUNDNESS")
	if msg := a.Check("lead", ""); !strings.Contains(msg, "verdict lead") {
		t.Errorf("SC-TRUST-SOUNDNESS must refuse a lead: %q", msg)
	}
}

func TestParseRejectsBadTables(t *testing.T) {
	for name, doc := range map[string]string{
		"no example":    `{"schema_version":"1","anchors":[{"id":"SC-A","pattern":"p","verdicts":["confirmed"],"severity":["low"],"ledger_classes":["x"],"vectors":[],"rule":"r"}],"examples":[]}`,
		"bad severity":  `{"schema_version":"1","anchors":[{"id":"SC-A","pattern":"p","verdicts":["confirmed"],"severity":["severe"],"ledger_classes":["x"],"vectors":[],"rule":"r"}],"examples":[{"anchor":"SC-A","source":"s","finding":"f","published":"Low","ref":"https://x"}]}`,
		"bad label":     `{"schema_version":"1","anchors":[{"id":"SC-A","pattern":"p","verdicts":["confirmed"],"severity":["low"],"ledger_classes":["x"],"vectors":[],"rule":"r"}],"examples":[{"anchor":"SC-A","source":"s","finding":"f","published":"Spicy","ref":"https://x"}]}`,
		"unknown field": `{"schema_version":"1","anchors":[],"examples":[],"extra":1}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
