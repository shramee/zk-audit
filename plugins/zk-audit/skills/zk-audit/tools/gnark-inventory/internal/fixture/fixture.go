// Package fixture locates the test fixtures. They live in the repository's
// top-level testdata/ directory, outside the skill folder, so a plugin or
// standalone install never ships fixtures with planted-bug comments. Only
// tests import this package.
package fixture

import (
	"os"
	"path/filepath"
	"testing"
)

// Root returns the repository's testdata directory, or "" when the tool runs
// outside a repository checkout (a standalone copy of the skill folder).
func Root() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".claude-plugin", "marketplace.json")); err == nil {
			return filepath.Join(dir, "testdata")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Dir returns testdata/<name> and skips the test when it does not exist.
func Dir(t testing.TB, name ...string) string {
	t.Helper()
	root := Root()
	if root == "" {
		t.Skip("fixtures live in the repository's testdata/; not in a checkout")
	}
	p := filepath.Join(append([]string{root}, name...)...)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s missing: %v", p, err)
	}
	return p
}
