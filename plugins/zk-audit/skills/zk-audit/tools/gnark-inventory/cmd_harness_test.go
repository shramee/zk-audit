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
