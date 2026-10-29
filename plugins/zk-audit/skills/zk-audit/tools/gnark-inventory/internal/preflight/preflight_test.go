package preflight

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
)

// fakeCache builds a module cache with the given module@version entries
// (source directory with a go.mod holding goDirective, and the download
// .mod/.zip pair) and toolchains.
func fakeCache(t *testing.T, mods map[string]string, toolchains ...string) string {
	t.Helper()
	c := t.TempDir()
	for mv, goDir := range mods {
		mod, ver, _ := strings.Cut(mv, "@")
		src := filepath.Join(c, filepath.FromSlash(mod)+"@"+ver)
		must(t, os.MkdirAll(filepath.Join(src, "std"), 0o755))
		must(t, os.WriteFile(filepath.Join(src, "go.mod"), []byte("module "+mod+"\n\ngo "+goDir+"\n"), 0o644))
		dl := filepath.Join(c, "cache", "download", filepath.FromSlash(mod), "@v")
		must(t, os.MkdirAll(dl, 0o755))
		must(t, os.WriteFile(filepath.Join(dl, ver+".mod"), []byte("module "+mod+"\n\ngo "+goDir+"\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(dl, ver+".zip"), []byte("zip"), 0o644))
	}
	for _, tc := range toolchains {
		bin := filepath.Join(c, "golang.org", "toolchain@v0.0.1-"+tc+"."+runtime.GOOS+"-"+runtime.GOARCH, "bin")
		must(t, os.MkdirAll(bin, 0o755))
		must(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\n"), 0o755))
	}
	return c
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func target(t *testing.T, gomod string) *detect.Stack {
	t.Helper()
	repo := t.TempDir()
	must(t, os.WriteFile(filepath.Join(repo, "go.mod"), []byte(gomod), 0o644))
	st, err := detect.Detect(repo, "test")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

const mod016 = `module example.com/t

go 1.26.8

require (
	github.com/consensys/gnark v0.16.4
	github.com/consensys/gnark-crypto v0.21.0
	github.com/x/dep v1.0.0 // indirect
)
`

func TestAllPresent(t *testing.T) {
	cache := fakeCache(t, map[string]string{
		"github.com/consensys/gnark@v0.16.4": "1.26.8", "github.com/consensys/gnark-crypto@v0.21.0": "1.25.7", "github.com/x/dep@v1.0.0": "1.20",
	}, "go1.25.7", "go1.26.10")
	r := Check(target(t, mod016), Options{Cache: cache, LocalGo: "go1.24.7", Out: "/o"})
	if !r.OK || len(r.Commands) != 0 {
		t.Fatalf("want ok with no commands: %s", r.Text())
	}
	m := r.Modules[0]
	if m.NeedsGo != "1.26.8" || m.LocalGoOK {
		t.Errorf("needs %s, local ok %v", m.NeedsGo, m.LocalGoOK)
	}
	// the oldest cached toolchain at least as new as go 1.26.8
	if !strings.Contains(m.UseGo, "go1.26.10") {
		t.Errorf("use go %q", m.UseGo)
	}
	if m.Std != filepath.Join(cache, "github.com/consensys/gnark@v0.16.4", "std") {
		t.Errorf("std %q", m.Std)
	}
	if !strings.HasPrefix(r.Summary, "preflight: ok") || !strings.Contains(r.Summary, m.Std) {
		t.Errorf("summary %q", r.Summary)
	}
}

func TestMissingEverything(t *testing.T) {
	cache := fakeCache(t, map[string]string{"github.com/consensys/gnark-crypto@v0.21.0": "1.25.7"})
	r := Check(target(t, mod016), Options{Cache: cache, LocalGo: "go1.24.7", Out: "/o"})
	if r.OK {
		t.Fatal("want missing")
	}
	txt := r.Text()
	for _, want := range []string{
		"github.com/consensys/gnark@v0.16.4 is not in the module cache",
		"2 of 3 requirements are not in the module cache",
		"command (network, ask first): go -C /o mod download github.com/consensys/gnark@v0.16.4\n",
		"command (ask first): git -C ",
		"command (network, ask first): go -C /o/worktree mod download",
		// gnark's go directive is unknown (not cached), the module's own is 1.26.8
		"command (network, ask first): GOTOOLCHAIN=go1.26.8 go -C /o version",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	for _, c := range r.Commands {
		if strings.Contains(c.Command, "&&") || strings.Contains(c.Command, ";") {
			t.Errorf("commands must be simple (allowlists refuse compound commands): %q", c.Command)
		}
	}
	if r.Modules[0].Std != "" {
		t.Errorf("no std path when gnark is missing")
	}
}

func TestGnarkDirectiveRaisesNeededGo(t *testing.T) {
	cache := fakeCache(t, map[string]string{"github.com/consensys/gnark@v0.15.0": "1.25.7"})
	r := Check(target(t, "module example.com/t\n\ngo 1.24.0\n\nrequire github.com/consensys/gnark v0.15.0\n"), Options{Cache: cache, LocalGo: "go1.24.7"})
	m := r.Modules[0]
	if m.NeedsGo != "1.25.7" || m.LocalGoOK || r.OK {
		t.Errorf("gnark v0.15.0 needs go 1.25.7: %+v", m)
	}
	if !strings.Contains(r.Text(), "GOTOOLCHAIN=go1.25.7 go -C <out> version") {
		t.Errorf("%s", r.Text())
	}
}

func TestNoGnark(t *testing.T) {
	r := Check(target(t, "module example.com/t\n\ngo 1.22\n"), Options{Cache: t.TempDir(), LocalGo: "go1.24.7"})
	if !r.OK || len(r.Modules) != 0 || !strings.Contains(r.Summary, "nothing to fetch") {
		t.Errorf("%+v", r)
	}
}
