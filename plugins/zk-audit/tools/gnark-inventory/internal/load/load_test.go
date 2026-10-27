package load

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetEnv(t *testing.T) {
	env := targetEnv([]string{"GOFLAGS=-mod=vendor -trimpath", "GOPROXY=https://proxy.golang.org", "HOME=/x"}, false)
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "-mod=") || !strings.Contains(joined, "-trimpath") || !strings.Contains(joined, "GOPROXY=off") || strings.Contains(joined, "proxy.golang.org") {
		t.Fatalf("env: %v", env)
	}
	env = targetEnv([]string{"GOPROXY=https://proxy.golang.org"}, true)
	if len(env) != 1 || env[0] != "GOPROXY=https://proxy.golang.org" {
		t.Fatalf("network env: %v", env)
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
