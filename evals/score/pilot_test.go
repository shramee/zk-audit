package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const pilotSrc = `package vote

func (c *Circuit) Define(api API) error {
	r := api.NewHint(sqrt, 1, c.X)
	// -
	// -
	// -
	// -
	// -
	// -
	// -
	api.AssertIsEqual(c.Y, c.Y)
	// -
	// -
	// -
	// -
	// -
	// -
	// -
	q := api.Div(c.A, c.B)
	_ = q
	// -
	// -
	// -
	// -
	// -
	// -
	// -
	z := c.Z
	_ = z
	return nil
}
`

const humanJSON = `{"schema_version": "1", "pilot": "pilot-1", "target": {"name": "vote", "commit": "0123456789abcdef"},
 "auditor": "A. Auditor", "report": "report.pdf",
 "findings": [
  {"id": "H-01", "title": "sqrt hint unbound", "severity": "critical", "file": "vote/c.go", "line": 4, "match": "(?i)hint|sqrt"},
  {"id": "H-02", "title": "Y constrained to itself", "severity": "high", "file": "vote/c.go", "line": 12},
  {"id": "H-03", "title": "division by zero", "severity": "medium", "file": "vote/c.go", "line": 20, "end_line": 21}
 ]}`

const humanMD = "# Pilot\n\nPilot: pilot-1\nTarget: vote\nCommit: `0123456789abcdef`\nAuditor: A. Auditor\n\n" +
	"| Id | Title | Severity | Location | Match |\n|---|---|---|---|---|\n" +
	"| H-01 | sqrt hint unbound | critical | `vote/c.go:4` | (?i)hint\\|sqrt |\n" +
	"| H-02 | Y constrained to itself | high | vote/c.go:12 | |\n" +
	"| H-03 | division by zero | medium | vote/c.go:20-21 | |\n"

func pilotFindings(recs ...string) string {
	return `{"records": [` + strings.Join(recs, ",") + `]}`
}

func rec(fp, verdict, title string, line int) string {
	b, _ := json.Marshal(map[string]any{"fingerprint": fp, "verdict": verdict, "title": title, "location": map[string]any{"file": "vote/c.go", "line": line}, "severity": "high"})
	return string(b)
}

func runPilot(t *testing.T, human, humanName, findings string) *PilotResult {
	t.Helper()
	dir := writeTree(t, map[string]string{"vote/c.go": pilotSrc, humanName: human, "findings.json": findings})
	var out bytes.Buffer
	if err := cmdPilot([]string{"--human", filepath.Join(dir, humanName), "--target", dir, "--findings", filepath.Join(dir, "findings.json"),
		"--key-out", filepath.Join(dir, "key.json")}, &out); err != nil {
		t.Fatal(err)
	}
	var p PilotResult
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	// the written key loads with the ordinary loader
	if _, err := loadKey(filepath.Join(dir, "key.json")); err != nil {
		t.Errorf("written key: %v", err)
	}
	return &p
}

func TestPilotPassAndFail(t *testing.T) {
	for _, h := range []struct{ body, name string }{{humanJSON, "human.json"}, {humanMD, "human.md"}} {
		// both high/critical findings caught (one only as a lead): pass
		p := runPilot(t, h.body, h.name, pilotFindings(
			rec("Circuit|r|hint-unbound", "confirmed", "sqrt hint output r is unconstrained", 4),
			rec("Circuit|Y|tautology", "lead", "Y is compared with itself", 12),
			rec("Circuit|Z|other", "confirmed", "something else", 29)))
		if !p.Pass || p.HighCritical != 2 || len(p.Found) != 1 || len(p.LeadOnly) != 1 || len(p.OtherMissed) != 1 {
			t.Errorf("%s: %+v", h.name, p)
		}
		if len(p.Unmatched) != 1 || !strings.Contains(p.Row, "| pilot-1 | vote | `0123456789` | 3 | 2 | 1 | 1 | 0 | pass |") {
			t.Errorf("%s: unmatched %v row %s", h.name, p.Unmatched, p.Row)
		}
		// a record at the right line about something else does not catch H-01
		// (match), and a rejected record does not catch H-02: both are misses
		p = runPilot(t, h.body, h.name, pilotFindings(
			rec("Circuit|r|style", "confirmed", "variable naming", 4),
			rec("Circuit|Y|tautology", "rejected", "Y is compared with itself", 12)))
		if p.Pass || strings.Join(p.Misses, ",") != "H-01 (critical),H-02 (high)" || !strings.Contains(p.Row, "FAIL") {
			t.Errorf("%s misses: %+v", h.name, p)
		}
	}
}

func TestPilotInputErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{"vote/c.go": pilotSrc,
		"sev.json":   strings.Replace(humanJSON, `"medium"`, `"severe"`, 1),
		"empty.md":   "# nothing\n",
		"badloc.md":  "| Id | Title | Severity | Location |\n|---|---|---|---|\n| H-1 | t | high | somewhere |\n",
		"range.json": strings.Replace(humanJSON, `"line": 20, "end_line": 21`, `"line": 20, "end_line": 70`, 1),
		"f.json":     `{"records": []}`})
	for _, name := range []string{"sev.json", "empty.md", "badloc.md", "range.json"} {
		var out bytes.Buffer
		err := cmdPilot([]string{"--human", filepath.Join(dir, name), "--target", dir, "--findings", filepath.Join(dir, "f.json")}, &out)
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
