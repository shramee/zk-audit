package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInsideResolvesSymlinks(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	other := filepath.Join(base, "other")
	os.MkdirAll(filepath.Join(repo, "sub"), 0o755)
	os.MkdirAll(other, 0o755)
	// a link outside the repo that points into it
	os.Symlink(repo, filepath.Join(base, "alias"))
	// a link inside the repo that points out of it
	os.Symlink(other, filepath.Join(repo, "escape"))
	cases := []struct {
		p    string
		want bool
	}{
		{filepath.Join(repo, "sub"), true},
		{filepath.Join(repo, "sub", "new", "file"), true},
		{repo, true},
		{filepath.Join(base, "alias", "out"), true},
		{filepath.Join(base, "alias", "not", "yet"), true},
		{filepath.Join(repo, "escape", "x"), false},
		{other, false},
		{filepath.Join(base, "repo2"), false},
		{filepath.Join(repo, "..", "other"), false},
	}
	for _, c := range cases {
		if got := Inside(c.p, repo); got != c.want {
			t.Errorf("Inside(%s) = %v, want %v", c.p, got, c.want)
		}
	}
	if !Inside(filepath.Join(repo, "x"), filepath.Join(base, "alias")) {
		t.Error("a symlinked root must match its target")
	}
}
