// Package fsutil walks a target repository with the skip rules shared by all
// subcommands.
package fsutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SkipDirs are directory names never descended into below the root:
// version control, editor state, Go vendor and testdata directories, and
// JavaScript dependency trees. Build-output names (out, build, cache) are not
// skipped because Go packages may use them; they hold no .go or .sol sources
// in Foundry or Hardhat layouts anyway.
var SkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".idea": true, ".vscode": true,
	"node_modules": true, "vendor": true, "testdata": true, ".zk-audit": true,
}

// File is one file found by Walk.
type File struct {
	Abs string
	Rel string // slash-separated, relative to root
}

// Walk returns every regular file under root whose name passes keep, skipping
// SkipDirs below the root. Results are sorted by Rel for determinism.
func Walk(root string, keep func(rel string) bool) ([]File, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []File
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			if p != root && SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if keep == nil || keep(rel) {
			out = append(out, File{Abs: p, Rel: rel})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, err
}

// HasExt returns a keep function matching any of the extensions.
func HasExt(exts ...string) func(string) bool {
	return func(rel string) bool {
		for _, e := range exts {
			if strings.HasSuffix(rel, e) {
				return true
			}
		}
		return false
	}
}

// Exists reports whether path exists.
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// InScope reports whether rel is selected by a --files filter. An empty filter
// selects everything. Filter entries may be files or directories.
func InScope(rel string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		f = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(f)), "/")
		if rel == f || strings.HasPrefix(rel, f+"/") {
			return true
		}
	}
	return false
}
