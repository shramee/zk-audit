package assemble

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden REPORT.golden.md files")

var poolRepo = filepath.Join("..", "..", "testdata", "pool")

func opts(dir string, withStack, withInv bool) Options {
	o := Options{
		Findings: filepath.Join("testdata", dir, "findings.json"),
		Ledger:   filepath.Join("testdata", dir, "coverage-ledger.json"),
		Repo:     poolRepo,
	}
	if withStack {
		o.Stack = filepath.Join("testdata", dir, "stack.json")
	}
	if withInv {
		o.Inventory = filepath.Join("testdata", dir, "inventory.json")
	}
	return o
}

func golden(t *testing.T, dir, got string) {
	t.Helper()
	p := filepath.Join("testdata", dir, "REPORT.golden.md")
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/assemble -update` to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the rendered report; rerun with -update after checking the diff.\n--- got ---\n%s", p, got)
	}
}

// forbidden are claims REPORT.md must never contain (SKILL.md hard rule 7).
var forbidden = regexp.MustCompile(`(?i)verified clean|fully audited|no vulnerabilities|no bugs|bug-free|\bis secure\b`)

func TestGoldenFull(t *testing.T) {
	res, err := Assemble(opts("full", true, true))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "full", res.Report)
	r := res.Report
	// sorted by severity, then confidence
	order := []string{"| 1 | Merkle leaf is not bound to the spent note [NEW] | critical | 95", "| 2 | Owner check is skipped when Index is non-zero | high | 85", "| 3 | Remainder hint output is never constrained | low | 70"}
	last := -1
	for _, s := range order {
		i := strings.Index(r, s)
		if i < 0 || i < last {
			t.Fatalf("findings table order: %q missing or out of order", s)
		}
		last = i
	}
	for _, want := range []string{
		"## 1. Scope", "## 2. Posture", "## 3. Findings", "## 4. Finding details", "## 5. Leads",
		"## 6. Needs validation", "## 7. Hardening notes", "## 8. Coverage",
		"\tcur := c.Path[0]\n", // verbatim quote from the source tree
		"Option A — bind the note", "Option B — use std/accumulator/merkle",
		"**Gates.**", // refuter said not_exploitable: both views are shown
		"Rejected candidates: 1",
		"Inventory load mode: `syntax` (1 load error)",
		"GHSA-7fx8-hmgc-82jp (high, fixed v0.16.4)",
		"Examined (covered or candidate): 3 of 6 applicable units (50%)",
		"`circuit:SigCircuit|crypto-gadgets` — planned — no reason recorded",
		"Smells: api.IsZero(c.Recipient) result dropped; Recipient | appears in no AssertIsEqual.",
		"Companions not available: circom-auditor, solidity-auditor",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if forbidden.MatchString(r) {
		t.Errorf("report makes a forbidden claim: %q", forbidden.FindString(r))
	}
	j := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"missing-fingerprint", "SigCircuit|crypto-gadgets is still planned"} {
		if !strings.Contains(j, want) {
			t.Errorf("warnings lack %q: %v", want, res.Warnings)
		}
	}
}

func TestGoldenEmpty(t *testing.T) {
	res, err := Assemble(opts("empty", false, false))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "empty", res.Report)
	r := res.Report
	if forbidden.MatchString(r) {
		t.Errorf("zero-finding report makes a forbidden claim: %q", forbidden.FindString(r))
	}
	for _, want := range []string{
		"No confirmed findings in the examined units.",
		"The absence of confirmed findings does not mean the code is free of bugs.",
		"The run recorded no findings: no candidate survived judging in the 2 covered units.",
		"| Stack | not recorded (no stack.json) |",
		"Examined (covered or candidate): 2 of 3 applicable units (66%)",
		"`circuit:Edge|field-arithmetic` — deferred — C3 is not in the quick profile",
		"Absence of a finding is not\n> evidence of absence of bugs.",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, err := Assemble(opts("full", true, true))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		b, err := Assemble(opts("full", true, true))
		if err != nil {
			t.Fatal(err)
		}
		if a.Report != b.Report {
			t.Fatal("two renders of the same input differ")
		}
	}
}

func writeCase(t *testing.T, findings, ledger string) Options {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "findings.json")
	l := filepath.Join(dir, "coverage-ledger.json")
	os.WriteFile(f, []byte(findings), 0o644)
	os.WriteFile(l, []byte(ledger), 0o644)
	return Options{Findings: f, Ledger: l}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRefusesInvalidInput(t *testing.T) {
	goodF := read(t, filepath.Join("testdata", "full", "findings.json"))
	goodL := read(t, filepath.Join("testdata", "full", "coverage-ledger.json"))
	cases := map[string]struct {
		f, l, want string
	}{
		"schema error in findings": {strings.Replace(goodF, `"severity": "critical"`, `"severity": "severe"`, 1), goodL, "findings"},
		"semantic error in findings": {strings.Replace(goodF, `"result": "demonstrated"`, `"result": "does_not_compile"`, 1), goodL, "evidence POC requires"},
		"empty findings without statement": {`{"schema_version":"1","repo":"r","run_id":"20261027-101500","profile":"quick","records":[]}`, goodL, "zero records"},
		"empty ledger": {goodF, `{"schema_version":"1","repo":"r","generated_by":"t","units":[]}`, "zero units"},
		"covered without evidence": {goodF, strings.Replace(goodL, `"agent_ids": ["V-range"]`, `"agent_ids": []`, 1), "covered units need agent_ids"},
		"clean claim in posture": {strings.Replace(goodF, `"posture": "Proofs gate`, `"posture": "The circuit is verified clean. Proofs gate`, 1), goodL, "forbidden claim"},
		"clean claim in no_findings_reason": {`{"schema_version":"1","repo":"r","run_id":"20261027-101500","profile":"quick","no_findings":true,"no_findings_reason":"the code is secure","records":[]}`, goodL, "forbidden claim"},
		"not json": {`{`, goodL, "findings"},
	}
	for name, c := range cases {
		_, err := Assemble(writeCase(t, c.f, c.l))
		if err == nil {
			t.Errorf("%s: expected refusal", name)
			continue
		}
		if !IsInvalid(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want InvalidError containing %q, got %v", name, c.want, err)
		}
	}
	if _, err := Assemble(Options{Findings: "nope.json", Ledger: "nope.json"}); err == nil || !IsInvalid(err) {
		t.Errorf("missing files: want InvalidError, got %v", err)
	}
}

func TestLocationPastEOFAndOptionPrefix(t *testing.T) {
	f := read(t, filepath.Join("testdata", "full", "findings.json"))
	f = strings.Replace(f, `"line": 90, "end_line": 91`, `"line": 190, "end_line": 191`, 1)
	f = strings.Replace(f, `"label": "bind the note"`, `"label": "Option A — bind the note"`, 1)
	o := writeCase(t, f, read(t, filepath.Join("testdata", "full", "coverage-ledger.json")))
	o.Repo = poolRepo
	res, err := Assemble(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "circuit/transfer.go:190-191 is past the end of circuit/transfer.go") {
		t.Errorf("no past-EOF warning: %v", res.Warnings)
	}
	if strings.Contains(res.Report, "Option A — Option A") || !strings.Contains(res.Report, "Option A — bind the note") {
		t.Error("option label prefix not normalised")
	}
}

func TestQuoteStaysInRepo(t *testing.T) {
	in := &input{repo: poolRepo}
	if _, _, ok := in.quote(Location{File: "../../main.go", Line: 1}); ok {
		t.Error("quote must not read outside the repository")
	}
	if _, _, ok := in.quote(Location{File: "/etc/passwd", Line: 1}); ok {
		t.Error("quote must not read absolute paths")
	}
	q, lang, ok := in.quote(Location{File: "circuit/transfer.go", Line: 1, EndLine: 200})
	if !ok || lang != "go" || !strings.Contains(q, "truncated after 30 lines") {
		t.Errorf("long quote not truncated: ok=%v lang=%s", ok, lang)
	}
}
