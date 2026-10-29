// Package modcache locates modules and Go toolchains in the Go module cache
// without running the go command on the target: the absolute gnark std
// directory that hunters read, and the pre-flight check of what an audit
// needs offline.
package modcache

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Dir returns GOMODCACHE: the environment, else `go env GOMODCACHE`, else
// GOPATH/pkg/mod.
func Dir() string {
	if c := os.Getenv("GOMODCACHE"); c != "" {
		return c
	}
	if c := goEnv("GOMODCACHE"); c != "" {
		return c
	}
	gp := os.Getenv("GOPATH")
	if gp == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gp = filepath.Join(h, "go")
	}
	return filepath.Join(strings.Split(gp, string(os.PathListSeparator))[0], "pkg", "mod")
}

// LocalGo returns the version of the go command on PATH ("go1.24.7"), or
// the version the tool was built with when there is none.
func LocalGo() string {
	if v := goEnv("GOVERSION"); v != "" {
		return v
	}
	return runtime.Version()
}

func goEnv(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "env", name)
	// never let `go env` switch or download a toolchain
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	o, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(o))
}

// Escape applies the module cache's case encoding: every upper-case letter
// becomes '!' followed by its lower-case form.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Module is what the cache holds of one module version.
type Module struct {
	Path    string `json:"module"`
	Version string `json:"version"`
	// Source is the extracted source directory (what agents read).
	Source        string `json:"source_dir"`
	SourcePresent bool   `json:"source_present"`
	// Download is the cache/download entry the go command builds from
	// offline (the .mod file; the .zip is checked too).
	Download        string `json:"download_mod"`
	DownloadPresent bool   `json:"download_present"`
	// GoDirective is the `go` line of the module's own go.mod, when the
	// cache has it.
	GoDirective string `json:"go_directive,omitempty"`
}

// Lookup describes module@version in cache.
func Lookup(cache, module, version string) Module {
	m := Module{Path: module, Version: version}
	if cache == "" {
		return m
	}
	esc := Escape(module)
	m.Source = filepath.Join(cache, filepath.FromSlash(esc)+"@"+Escape(version))
	if st, err := os.Stat(m.Source); err == nil && st.IsDir() {
		m.SourcePresent = true
	}
	dl := filepath.Join(cache, "cache", "download", filepath.FromSlash(esc), "@v", Escape(version))
	m.Download = dl + ".mod"
	_, e1 := os.Stat(dl + ".mod")
	_, e2 := os.Stat(dl + ".zip")
	m.DownloadPresent = e1 == nil && e2 == nil
	for _, p := range []string{filepath.Join(m.Source, "go.mod"), dl + ".mod"} {
		if g := goDirective(p); g != "" {
			m.GoDirective = g
			break
		}
	}
	return m
}

func goDirective(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "go" {
			return f[1]
		}
	}
	return ""
}

// Toolchain is a Go toolchain module in the cache
// (golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64).
type Toolchain struct {
	Version string `json:"version"` // go1.25.7
	GoBin   string `json:"go"`      // absolute path of its bin/go
}

// Toolchains lists the toolchains for this OS and architecture in the
// cache, oldest first.
func Toolchains(cache string) []Toolchain {
	if cache == "" {
		return nil
	}
	dir := filepath.Join(cache, "golang.org")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	suffix := "." + runtime.GOOS + "-" + runtime.GOARCH
	var out []Toolchain
	for _, e := range ents {
		name := e.Name()
		v, ok := strings.CutPrefix(name, "toolchain@v0.0.1-")
		if !ok || !strings.HasSuffix(v, suffix) {
			continue
		}
		v = strings.TrimSuffix(v, suffix)
		bin := filepath.Join(dir, name, "bin", "go")
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		out = append(out, Toolchain{Version: v, GoBin: bin})
	}
	sort.Slice(out, func(i, j int) bool { return CompareGo(out[i].Version, out[j].Version) < 0 })
	return out
}

// CompareGo compares Go versions written as "1.24", "1.24.0", "go1.25.7"
// or "go1.21rc1" (a release candidate sorts before the release).
func CompareGo(a, b string) int {
	pa, ra := goParts(a)
	pb, rb := goParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case ra == rb:
		return 0
	case ra == "":
		return 1
	case rb == "":
		return -1
	case ra < rb:
		return -1
	}
	return 1
}

func goParts(v string) ([3]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "go")
	if i := strings.IndexAny(v, " -"); i >= 0 {
		v = v[:i]
	}
	pre := ""
	for _, tag := range []string{"rc", "beta"} {
		if i := strings.Index(v, tag); i >= 0 {
			pre, v = v[i:], v[:i]
		}
	}
	var out [3]int
	for i, p := range strings.SplitN(v, ".", 3) {
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out, pre
}
