package load

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetEnv(t *testing.T) {
	env := targetEnv([]string{"GOFLAGS=-mod=vendor -toolexec=/evil", "GOPROXY=https://proxy.golang.org", "HOME=/x",
		"CGO_ENABLED=1", "GOWORK=/parent/go.work", "GOTOOLCHAIN=auto"}, false)
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := m[k]; dup {
			t.Errorf("%s set twice: %v", k, env)
		}
		m[k] = v
	}
	want := map[string]string{"GOFLAGS": "", "GOPROXY": "off", "CGO_ENABLED": "0", "GOWORK": "off", "GOTOOLCHAIN": "local", "HOME": "/x"}
	for k, v := range want {
		if got, ok := m[k]; !ok || got != v {
			t.Errorf("%s=%q, want %q (env %v)", k, got, v, env)
		}
	}
	env = targetEnv([]string{"GOPROXY=https://proxy.golang.org", "GOTOOLCHAIN=auto", "CGO_ENABLED=1"}, true)
	joined := strings.Join(env, " ")
	for _, w := range []string{"GOPROXY=https://proxy.golang.org", "GOTOOLCHAIN=auto", "CGO_ENABLED=0", "GOWORK=off"} {
		if !strings.Contains(joined, w) {
			t.Errorf("network env lacks %s: %v", w, env)
		}
	}
	if strings.Contains(joined, "CGO_ENABLED=1") {
		t.Errorf("cgo kept with network: %v", env)
	}
}

func TestSyntaxFallback(t *testing.T) {
	dir := t.TempDir()
	// no go.mod: typed loading is not attempted, every file is parsed
	src := "package x\n\nimport fe \"github.com/consensys/gnark/frontend\"\n\ntype C struct{ A fe.Variable }\n"
	if err := os.WriteFile(filepath.Join(dir, "c.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package x\nfunc {"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if prog.Mode != "syntax" || len(prog.Files) < 1 {
		t.Fatalf("mode %s files %d", prog.Mode, len(prog.Files))
	}
	if prog.Files[len(prog.Files)-1].Imports["fe"] != "github.com/consensys/gnark/frontend" {
		t.Fatalf("aliased import not recorded: %v", prog.Files[0].Imports)
	}
}

func TestDefaultImportName(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/consensys/gnark/std/algebra/emulated/sw_emulated": "sw_emulated",
		"github.com/foo/bar/v2":   "bar",
		"github.com/foo/go-thing": "thing",
	} {
		if got := defaultImportName(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
}

func TestBuildDirNotSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build", "b.go"), []byte("package build\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := Load(dir, Options{SyntaxOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Files) != 1 {
		t.Fatalf("a Go package named build must be loaded, got %d files", len(prog.Files))
	}
}

// TestEnclosingModule loads a package directory that has no go.mod of its
// own (a gnark std package in the module cache) with the enclosing module.
func TestEnclosingModule(t *testing.T) {
	mod := t.TempDir()
	sub := filepath.Join(mod, "std", "widget")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "w.go"), []byte("package widget\n\nfunc Double(x int) int { return 2 * x }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := Load(sub, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if prog.Mode != "types" || len(prog.Files) != 1 || prog.Files[0].Rel != "w.go" || prog.Files[0].Pkg.PkgPath != "example.com/m/std/widget" {
		t.Fatalf("mode %s files %d errors %v", prog.Mode, len(prog.Files), prog.Errors)
	}
}
