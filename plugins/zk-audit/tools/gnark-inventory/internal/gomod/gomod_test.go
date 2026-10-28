package gomod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	src := `module example.com/zk // comment

go 1.24.0

toolchain go1.24.7

require github.com/consensys/gnark v0.12.0

require (
	github.com/consensys/gnark-crypto v0.15.0 // indirect
	golang.org/x/crypto v0.30.0
)

replace github.com/consensys/gnark-crypto => ../gnark-crypto
replace (
	github.com/consensys/gnark v0.12.0 => github.com/fork/gnark v0.12.1-fork
)
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.Module != "example.com/zk" || f.Go != "1.24.0" || f.Toolchain != "go1.24.7" {
		t.Fatalf("header: %+v", f)
	}
	if len(f.Require) != 3 || !f.Require[1].Indirect {
		t.Fatalf("require: %+v", f.Require)
	}
	v, by, ok := f.Version("github.com/consensys/gnark")
	if !ok || v != "v0.12.1-fork" || by != "github.com/fork/gnark" {
		t.Fatalf("gnark version: %q %q %v", v, by, ok)
	}
	v, by, ok = f.Version("github.com/consensys/gnark-crypto")
	if !ok || v != "" || by != "../gnark-crypto" {
		t.Fatalf("gnark-crypto version: %q %q %v", v, by, ok)
	}
}
