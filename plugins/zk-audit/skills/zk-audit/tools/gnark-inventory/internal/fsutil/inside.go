package fsutil

import (
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns the absolute, symlink-free form of p. A path that does not
// exist yet is resolved through its longest existing ancestor, so a symlinked
// parent cannot hide where a new file would land.
func Resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var tail []string
	cur := abs
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			parts := append([]string{real}, tail...)
			return filepath.Join(parts...), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

// Inside reports whether p is root or lies under it, after resolving
// symlinks in both.
func Inside(p, root string) bool {
	rp, err := Resolve(p)
	if err != nil {
		return false
	}
	rr, err := Resolve(root)
	if err != nil {
		return false
	}
	return within(rp, rr)
}

// within reports whether the clean absolute path p is root or under it.
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
