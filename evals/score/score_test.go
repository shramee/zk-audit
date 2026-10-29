package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const src = `package c

func Define() {
	a := hint()
	_ = a
	b := x / y
	c := z
}
`

const keyJSON = `{
  "schema_version": "1", "case": "toy", "fixture": "toy",
  "items": [
    {"id": "P1", "title": "hint unbound", "class": "soundness", "critical": true,
     "ranges": [{"file": "c/c.go", "anchors": ["a := hint()", "_ = a"]}],
     "match": "(?i)hint", "expect": ["confirmed"], "partial": ["lead", "needs_validation"], "severity": ["high", "critical"]},
    {"id": "P2", "title": "division", "ranges": [{"file": "c/c.go", "anchors": ["b := x / y"]}],
     "match": "(?i)div", "expect": ["lead", "hardening", "confirmed"]}
  ],
  "decoys": [{"id": "D1", "title": "c is fine", "ranges": [{"file": "c/c.go", "anchors": ["c := z"]}], "match": "(?i)\\bc\\b"}],
  "other": []
}`

func setup(t *testing.T, findings string) (*Key, []entry) {
	t.Helper()
	dir := writeTree(t, map[string]string{"c/c.go": src, "key.json": keyJSON, "findings.json": findings})
	k, err := loadKey(filepath.Join(dir, "key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.resolve(dir); err != nil {
		t.Fatal(err)
	}
	es, err := loadFindings(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return k, es
}

func TestScoreFoundPartialFalsePositive(t *testing.T) {
	k, es := setup(t, `{"records": [
	  {"verdict": "confirmed", "title": "Hint output a is free", "location": {"file": "c/c.go", "line": 4}, "severity": "critical", "layer": "circuit", "evidence": "POC", "poc": {"path": "p", "result": "demonstrated"}},
	  {"verdict": "confirmed", "title": "c is wrong", "location": {"file": "c/c.go", "line": 7}, "severity": "low", "layer": "circuit"},
	  {"verdict": "needs_validation", "title": "Unrelated claim", "location": {"file": "other.go", "line": 1}, "severity": "low"},
	  {"verdict": "lead", "title": "Noise lead", "location": {"file": "other.go", "line": 1}}],
	  "hardening": [{"title": "div by zero", "location": {"file": "./c/c.go", "line": 6}}]}`)
	r := score(k, es)
	if r.Items[0].Outcome != "found" || r.Items[1].Outcome != "found" {
		t.Fatalf("items: %+v", r.Items)
	}
	if *r.Recall != 1 || *r.CriticalRecall != 1 {
		t.Errorf("recall %v critical %v", *r.Recall, *r.CriticalRecall)
	}
	if r.Decoys[0].Outcome != "false_positive" || len(r.FalsePositives) != 2 {
		t.Errorf("decoy %+v fps %v", r.Decoys[0], r.FalsePositives)
	}
	if len(r.Noise) != 1 || !strings.Contains(r.Noise[0], "Noise lead") {
		t.Errorf("noise %v", r.Noise)
	}
	if *r.SeverityAgree != 1 {
		t.Errorf("severity agreement %v", *r.SeverityAgree)
	}
	if *r.PoCRate != 0.5 {
		t.Errorf("poc rate %v", *r.PoCRate)
	}
}

func TestScorePartialAndMissed(t *testing.T) {
	k, es := setup(t, `{"records": [
	  {"verdict": "lead", "title": "hint maybe free", "location": {"file": "c/c.go", "line": 1, "end_line": 2}}]}`)
	r := score(k, es)
	if r.Items[0].Outcome != "partial" || r.Items[1].Outcome != "missed" {
		t.Fatalf("items: %+v", r.Items)
	}
	if *r.Recall != 0.25 || *r.CriticalRecall != 0.5 {
		t.Errorf("recall %v critical %v", *r.Recall, *r.CriticalRecall)
	}
	if r.Decoys[0].Outcome != "handled" {
		t.Errorf("decoy %+v", r.Decoys[0])
	}
}

func TestDescriptionMustMatch(t *testing.T) {
	k, es := setup(t, `{"records": [
	  {"verdict": "confirmed", "title": "Something else entirely", "location": {"file": "c/c.go", "line": 4}, "severity": "high"}]}`)
	r := score(k, es)
	if r.Items[0].Outcome != "missed" || len(r.FalsePositives) != 1 {
		t.Fatalf("a record at the right line with the wrong defect must not count: %+v %v", r.Items[0], r.FalsePositives)
	}
}

func TestMissingAnchorFails(t *testing.T) {
	dir := writeTree(t, map[string]string{"c/c.go": "package c\n", "key.json": keyJSON})
	k, err := loadKey(filepath.Join(dir, "key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.resolve(dir); err == nil {
		t.Fatal("drifted key must fail")
	}
}

// An all-safe fixture has no planted items: recall is undefined (nil), a clean
// report scores no false positives, and a confirmed record is a false positive.
func TestAllSafeNoItems(t *testing.T) {
	const safeKey = `{"schema_version": "1", "case": "safe", "fixture": "safe",
	  "items": [],
	  "decoys": [{"id": "D1", "title": "near-miss", "ranges": [{"file": "c/c.go", "anchors": ["b := x / y"]}], "match": "(?i)div"}],
	  "other": []}`
	dir := writeTree(t, map[string]string{"c/c.go": src, "key.json": safeKey})
	k, err := loadKey(filepath.Join(dir, "key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.resolve(dir); err != nil {
		t.Fatal(err)
	}
	clean, err := loadFindings(writeFindings(t, dir, `{"records": [], "hardening": []}`))
	if err != nil {
		t.Fatal(err)
	}
	r := score(k, clean)
	if r.Recall != nil {
		t.Errorf("recall must be nil for an all-safe fixture, got %v", *r.Recall)
	}
	if len(r.FalsePositives) != 0 {
		t.Errorf("a clean report on a safe fixture has no false positives: %v", r.FalsePositives)
	}
	// A confirmed record on the near-miss shape is a false positive.
	fp, err := loadFindings(writeFindings(t, dir, `{"records": [
	  {"verdict": "confirmed", "title": "division is unsound", "location": {"file": "c/c.go", "line": 6}, "severity": "high"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r = score(k, fp)
	if len(r.FalsePositives) != 1 {
		t.Errorf("a confirmed record on a safe fixture is a false positive: %v", r.FalsePositives)
	}
	// Summaries print recall as "–" for the all-safe run.
	out := summarize([]*Result{score(k, clean)})
	if !strings.Contains(out, "| safe | 1 | – |") {
		t.Errorf("all-safe recall should render as \"–\":\n%s", out)
	}
}

func writeFindings(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSummarize(t *testing.T) {
	k, es := setup(t, `{"records": []}`)
	a := score(k, es)
	a.Label = "run1"
	b := score(k, es)
	b.Items[0].Outcome = "found"
	half := 0.5
	b.Recall = &half
	out := summarize([]*Result{a, b})
	for _, want := range []string{"| toy | 2 | 25 % ± 35 (0–50) |", "| P1 | hint unbound | missed · found |"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}

// A dependency record that lists the item's file only as a related location
// must not outrank the record that sits on the item when both are in an
// accepted class, even when its verdict is stronger: the item's best record
// (and so its severity check) is the better-placed one.
func TestRecordOnTheItemBeatsRelatedMention(t *testing.T) {
	k, es := setup(t, `{"records": [
	  {"verdict": "confirmed", "title": "Library advisory covers division", "location": {"file": "go.mod", "line": 3},
	   "related_locations": [{"file": "c/c.go", "line": 6}], "severity": "medium"},
	  {"verdict": "lead", "title": "Division by y is unchecked", "location": {"file": "c/c.go", "line": 6}}]}`)
	r := score(k, es)
	if r.Items[1].Best != "lead" || r.Items[1].SeverityOK != nil {
		t.Fatalf("the record on the item must be the best one: %+v", r.Items[1])
	}
}
