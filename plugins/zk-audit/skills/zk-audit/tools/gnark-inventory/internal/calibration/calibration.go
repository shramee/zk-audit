// Package calibration holds the severity calibration anchors
// (calibration.json, embedded; references/severity-calibration.md carries
// the same JSON). Each anchor fixes the verdicts and severities allowed for
// one fact pattern, and cites published audit findings with their labels.
// `validate findings` checks a record's `calibration` against its anchor;
// `lint-kb` checks the anchors against the knowledge base.
package calibration

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed calibration.json
var raw []byte

// Raw returns the embedded JSON.
func Raw() []byte { return raw }

// Anchor is one calibrated fact pattern.
type Anchor struct {
	ID            string   `json:"id"`
	Pattern       string   `json:"pattern"`
	Verdicts      []string `json:"verdicts"`
	Severity      []string `json:"severity"`
	LedgerClasses []string `json:"ledger_classes"`
	Vectors       []string `json:"vectors"`
	Rule          string   `json:"rule"`
}

// Example is one published finding with its published severity label.
type Example struct {
	Anchor    string `json:"anchor"`
	Source    string `json:"source"`
	Finding   string `json:"finding"`
	Published string `json:"published"`
	Ref       string `json:"ref"`
}

// Table is the document.
type Table struct {
	Comment       string    `json:"$comment"`
	SchemaVersion string    `json:"schema_version"`
	Anchors       []Anchor  `json:"anchors"`
	Examples      []Example `json:"examples"`
}

var (
	reID       = regexp.MustCompile(`^SC-[A-Z0-9]+(-[A-Z0-9]+)*$`)
	verdicts   = map[string]bool{"confirmed": true, "needs_validation": true, "rejected": true, "lead": true}
	severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	published  = map[string]bool{"Critical": true, "High": true, "Medium": true, "Moderate": true, "Low": true, "Informational": true, "unrated": true}
)

var loaded *Table

// Load parses the embedded table; it panics on a malformed document (a test
// checks it).
func Load() *Table {
	if loaded != nil {
		return loaded
	}
	t, err := Parse(raw)
	if err != nil {
		panic("calibration.json: " + err.Error())
	}
	loaded = t
	return t
}

// Parse decodes and checks a calibration document's own consistency.
func Parse(b []byte) (*Table, error) {
	var t Table
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	var problems []string
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	if t.SchemaVersion != "1" {
		bad("schema_version %q, want 1", t.SchemaVersion)
	}
	ids := map[string]bool{}
	for _, a := range t.Anchors {
		if !reID.MatchString(a.ID) || ids[a.ID] {
			bad("anchor %q: id must match %s and be unique", a.ID, reID)
		}
		ids[a.ID] = true
		if a.Pattern == "" || a.Rule == "" {
			bad("anchor %s: pattern and rule are required", a.ID)
		}
		if len(a.Verdicts) == 0 || len(a.Severity) == 0 || len(a.LedgerClasses) == 0 {
			bad("anchor %s: verdicts, severity and ledger_classes are required", a.ID)
		}
		for _, v := range a.Verdicts {
			if !verdicts[v] {
				bad("anchor %s: unknown verdict %q", a.ID, v)
			}
		}
		for _, s := range a.Severity {
			if !severities[s] {
				bad("anchor %s: unknown severity %q", a.ID, s)
			}
		}
	}
	used := map[string]int{}
	for i, e := range t.Examples {
		if !ids[e.Anchor] {
			bad("examples[%d]: unknown anchor %q", i, e.Anchor)
		}
		used[e.Anchor]++
		if e.Source == "" || e.Finding == "" || e.Ref == "" {
			bad("examples[%d]: source, finding and ref are required", i)
		}
		if !published[e.Published] {
			bad("examples[%d]: published label %q is not one of Critical, High, Medium, Moderate, Low, Informational, unrated", i, e.Published)
		}
	}
	for _, a := range t.Anchors {
		if used[a.ID] == 0 {
			bad("anchor %s: no published example", a.ID)
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return &t, nil
}

// Anchor returns the anchor with this id.
func (t *Table) Anchor(id string) (*Anchor, bool) {
	for i := range t.Anchors {
		if t.Anchors[i].ID == id {
			return &t.Anchors[i], true
		}
	}
	return nil, false
}

// Check reports why a record's verdict and severity do not fit the anchor
// (empty when they fit). Severity is only checked for verdicts that carry
// one (confirmed, needs_validation).
func (a *Anchor) Check(verdict, severity string) string {
	if !contains(a.Verdicts, verdict) {
		return fmt.Sprintf("verdict %s is not allowed by %s (allowed: %s)", verdict, a.ID, strings.Join(a.Verdicts, ", "))
	}
	if (verdict == "confirmed" || verdict == "needs_validation") && !contains(a.Severity, severity) {
		return fmt.Sprintf("severity %s is not allowed by %s (allowed: %s; %s)", severity, a.ID, strings.Join(a.Severity, ", "), a.Rule)
	}
	return ""
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
