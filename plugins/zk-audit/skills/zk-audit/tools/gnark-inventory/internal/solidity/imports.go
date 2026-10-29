package solidity

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Import is one `import` directive of a scanned file and where it resolves.
type Import struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Path string `json:"path"`
	// Resolved is the repository-relative file the path names, or "" when
	// it does not exist in the repository.
	Resolved string `json:"resolved,omitempty"`
	// Via: relative, remapping, root, lib, node_modules, unresolved.
	Via string `json:"via"`
}

// Remapping is one Solidity import remapping (`prefix=target`), from
// remappings.txt, foundry.toml or Foundry's automatic lib/<name>/src rule.
type Remapping struct {
	Context string `json:"context,omitempty"`
	Prefix  string `json:"prefix"`
	Target  string `json:"target"`
	Source  string `json:"source"`
}

var (
	reImport      = regexp.MustCompile(`(?m)^\s*import\s+(?:[^;"']*?\bfrom\s+)?["']([^"']+)["'][^;]*;`)
	reTomlRemaps  = regexp.MustCompile(`(?s)\bremappings\s*=\s*\[(.*?)\]`)
	reTomlString  = regexp.MustCompile(`["']([^"']+)["']`)
	reTomlSection = regexp.MustCompile(`(?m)^\s*\[([^\]]+)\]\s*$`)
)

// LoadRemappings reads remappings.txt and foundry.toml files under root (at
// the root and next to every foundry.toml) and adds Foundry's automatic
// `<name>/=lib/<name>/src/` (or `lib/<name>/`) remappings. Paths in the
// result are repository-relative.
func LoadRemappings(root string, tomls []string) []Remapping {
	var out []Remapping
	seen := map[string]bool{}
	add := func(dir, line, source string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		ctx := ""
		if i := strings.Index(line, ":"); i >= 0 && i < strings.Index(line, "=") {
			ctx, line = line[:i], line[i+1:]
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			return
		}
		r := Remapping{Context: ctx, Prefix: line[:eq], Target: path.Clean(path.Join(dir, line[eq+1:])), Source: source}
		if strings.HasSuffix(line[eq+1:], "/") {
			r.Target += "/"
		}
		k := r.Context + "|" + r.Prefix
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, r)
	}
	dirs := []string{"."}
	for _, t := range tomls {
		if d := path.Dir(t); d != "." {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		if b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(d), "remappings.txt")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				add(d, l, path.Join(d, "remappings.txt"))
			}
		}
		if b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(d), "foundry.toml")); err == nil {
			s := string(b)
			// only the default profile's remappings
			sec := reTomlSection.FindAllStringSubmatchIndex(s, -1)
			for i, m := range sec {
				name := strings.TrimSpace(s[m[2]:m[3]])
				if name != "profile.default" && name != "default" {
					continue
				}
				end := len(s)
				if i+1 < len(sec) {
					end = sec[i+1][0]
				}
				if rm := reTomlRemaps.FindStringSubmatch(s[m[1]:end]); rm != nil {
					for _, q := range reTomlString.FindAllStringSubmatch(rm[1], -1) {
						add(d, q[1], path.Join(d, "foundry.toml"))
					}
				}
			}
		}
		libDir := filepath.Join(root, filepath.FromSlash(d), "lib")
		ents, err := os.ReadDir(libDir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			target := path.Join(d, "lib", e.Name())
			if st, err := os.Stat(filepath.Join(libDir, e.Name(), "src")); err == nil && st.IsDir() {
				target += "/src"
			}
			add(".", e.Name()+"/="+target+"/", "lib/ (Foundry automatic)")
		}
	}
	// longest prefix first, so `@oz/contracts/` wins over `@oz/`
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Prefix) > len(out[j].Prefix) })
	return out
}

// resolveImport maps an import path of file `from` to a repository-relative
// file. exists reports whether a relative path is a file.
func resolveImport(from, p string, remaps []Remapping, exists func(string) bool) (string, string) {
	if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
		r := path.Clean(path.Join(path.Dir(from), p))
		if exists(r) {
			return r, "relative"
		}
		return "", "unresolved"
	}
	for _, rm := range remaps {
		if rm.Context != "" && !strings.HasPrefix(from, strings.TrimSuffix(rm.Context, "/")) {
			continue
		}
		if strings.HasPrefix(p, rm.Prefix) {
			r := path.Clean(strings.TrimSuffix(rm.Target, "/") + "/" + strings.TrimPrefix(p, rm.Prefix))
			if exists(r) {
				return r, "remapping"
			}
		}
	}
	if exists(path.Clean(p)) {
		return path.Clean(p), "root"
	}
	for _, pre := range []string{"lib/", "node_modules/"} {
		if r := path.Clean(pre + p); exists(r) {
			return r, strings.TrimSuffix(pre, "/")
		}
	}
	// a path relative to the importing file's directory without ./ (solc
	// does not do this, but some repositories rely on base paths)
	if r := path.Clean(path.Join(path.Dir(from), p)); exists(r) {
		return r, "relative"
	}
	return "", "unresolved"
}

// importsOf lists the import directives of a source (comments stripped).
func importsOf(rel, src string, li lineIndex) []Import {
	var out []Import
	for _, m := range reImport.FindAllStringSubmatchIndex(src, -1) {
		out = append(out, Import{File: rel, Line: li.line(m[2]), Path: src[m[2]:m[3]]})
	}
	return out
}
