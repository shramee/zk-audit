package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
)

// TestHarnessMatchesEvalPoCs regenerates the per-gadget harness of the
// lib-gadgets fixture and compares it with the copies the eval PoCs build
// on (evals/fixtures/lib-gadgets/pocs, run by `make eval-pocs`), so the
// generator cannot drift from code that is known to compile and run.
func TestHarnessMatchesEvalPoCs(t *testing.T) {
	repo := fixture.Dir(t, "lib-gadgets")
	pocs := filepath.Join(filepath.Dir(fixture.Root()), "evals", "fixtures", "lib-gadgets", "pocs")
	out := t.TempDir()
	var buf bytes.Buffer
	if code := run([]string{"inventory", "--repo", repo, "--out", out, "--syntax-only"}, &buf, &buf); code != 0 {
		t.Fatalf("inventory: %s", buf.String())
	}
	wt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(wt, "gadgets"), 0o755); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if code := run([]string{"harness", "--out", out, "--all", "--worktree", wt}, &buf, &buf); code != 0 {
		t.Fatalf("harness: %s", buf.String())
	}
	if n := strings.Count(buf.String(), "→"); n != 9 {
		t.Errorf("want 9 harness files, got %d:\n%s", n, buf.String())
	}
	committed, _ := filepath.Glob(filepath.Join(pocs, "zkaudit_harness_*_test.go"))
	if len(committed) == 0 {
		t.Fatal("no committed harness copies in " + pocs)
	}
	for _, c := range committed {
		want, _ := os.ReadFile(c)
		got, err := os.ReadFile(filepath.Join(wt, "gadgets", filepath.Base(c)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from the generated harness (regenerate it with `gnark-inventory harness`): %v", filepath.Base(c), err)
		}
	}
	// the harness never goes into the audited repository
	buf.Reset()
	if code := run([]string{"harness", "--out", out, "--gadget", "G4", "--worktree", repo}, &buf, &buf); code != 2 || !strings.Contains(buf.String(), "inside the audited repository") {
		t.Errorf("writing into the repository must be refused (exit 2), got %d: %s", code, buf.String())
	}
}

// TestLibraryModeEndToEnd runs the deterministic library-mode pipeline on
// the lib-gadgets fixture: detect says library, the ledger has one
// doc-contract unit per gadget, the library profile bundles L1, and the
// report carries the gadget contract table.
func TestLibraryModeEndToEnd(t *testing.T) {
	repo := fixture.Dir(t, "lib-gadgets")
	out := t.TempDir()
	var buf bytes.Buffer
	if code := run([]string{"inventory", "--repo", repo, "--out", out, "--syntax-only"}, &buf, &buf); code != 0 {
		t.Fatalf("inventory: %s", buf.String())
	}
	stack, _ := os.ReadFile(filepath.Join(out, "stack.json"))
	if !strings.Contains(string(stack), `"mode": true`) {
		t.Errorf("stack.json library mode:\n%s", stack)
	}
	led, _ := os.ReadFile(filepath.Join(out, "coverage-ledger.json"))
	if n := strings.Count(string(led), `|doc-contract"`); n != 9 {
		t.Errorf("want 9 doc-contract units, got %d", n)
	}
	buf.Reset()
	if code := run([]string{"bundle", "--out", out, "--skill", filepath.Join("..", ".."), "--profile", "library"}, &buf, &buf); code != 0 {
		t.Fatalf("bundle: %s", buf.String())
	}
	l1, err := os.ReadFile(filepath.Join(out, "bundles", "L1.md"))
	if err != nil || !strings.Contains(string(l1), "- gadget G6 `gadgets.ToBits`") || !strings.Contains(string(l1), "doc checks: promise-boolean, promise-range") {
		t.Errorf("L1 bundle lacks the gadget lines: %v", err)
	}
	f := `{"schema_version":"1","repo":"lib-gadgets","run_id":"20261029-120000","profile":"library","records":[],"no_findings":true,"no_findings_reason":"pipeline test"}`
	if err := os.WriteFile(filepath.Join(out, "findings.json"), []byte(f), 0o644); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if code := run([]string{"assemble", "--out", out, "--repo", repo}, &buf, &buf); code != 0 {
		t.Fatalf("assemble: %s", buf.String())
	}
	rep, _ := os.ReadFile(filepath.Join(out, "REPORT.md"))
	for _, want := range []string{"### Gadget contracts", "| G9 | `gadgets.Canonical` | `gadgets/field.go:9` | range, canonical | – | promise-range, promise-canonical | planned | – |"} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
