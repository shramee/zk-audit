package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

func TestDetectPool(t *testing.T) {
	st, err := Detect(fixture.Dir(t, "pool"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Gnark.Present || len(st.Gnark.Versions) != 1 || st.Gnark.Versions[0] != "v0.14.0" {
		t.Fatalf("gnark: %+v", st.Gnark)
	}
	ids := map[string]bool{}
	for _, a := range st.Gnark.Advisories {
		ids[a.ID] = true
	}
	for _, want := range []string{"GHSA-7fx8-hmgc-82jp", "GHSA-3mvx-pp85-pm65", "GHSA-fwf3-jmp7-gmrj"} {
		if !ids[want] {
			t.Errorf("v0.14.0 should match %s", want)
		}
	}
	if ids["GHSA-95v9-hv42-pwrj"] {
		t.Error("v0.14.0 includes the CVE-2025-57801 fix")
	}
	if len(st.Gnark.Backends) != 1 || st.Gnark.Backends[0] != "groth16" {
		t.Errorf("backends %v", st.Gnark.Backends)
	}
	if len(st.Gnark.Curves) != 1 || st.Gnark.Curves[0] != "bn254" {
		t.Errorf("curves %v", st.Gnark.Curves)
	}
	if !st.Foundry.Present || !st.Solidity.Present || len(st.Solidity.Verifiers) != 1 {
		t.Errorf("solidity/foundry: %+v %+v", st.Solidity, st.Foundry)
	}
	b, _ := json.Marshal(st)
	rep, err := validate.Document("stack", b)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("stack.json does not validate: %v", rep.Errors)
	}
}

func TestDetectNothing(t *testing.T) {
	st, err := Detect(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if st.Gnark.Present || len(st.Notes) == 0 {
		t.Fatalf("empty repo should note that zk-audit does not fit: %+v", st.Notes)
	}
}

func TestLibraryMode(t *testing.T) {
	st, err := Detect(fixture.Dir(t, "lib-gadgets"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if l := st.Library; !l.Mode || l.Gadgets != 7 || l.ProductionCircuits != 0 || strings.Join(l.Packages, ",") != "gadgets" {
		t.Errorf("lib-gadgets: %+v", l)
	}
	st, err = Detect(fixture.Dir(t, "pool"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if st.Library.Mode || st.Library.ProductionCircuits == 0 {
		t.Errorf("pool has production circuits: %+v", st.Library)
	}
}

func TestEnclosingModuleAndGnarkItself(t *testing.T) {
	// a std package directory inside a gnark checkout in the module cache
	mod := filepath.Join(t.TempDir(), "github.com", "consensys", "gnark@v0.12.0")
	pkg := filepath.Join(mod, "std", "math", "widget")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(mod, "go.mod"), "module github.com/consensys/gnark\n\ngo 1.22\n\nrequire github.com/consensys/gnark-crypto v0.15.0\n")
	write(filepath.Join(pkg, "w.go"), "package widget\n\nimport \"github.com/consensys/gnark/frontend\"\n\n// Double returns 2v.\nfunc Double(api frontend.API, v frontend.Variable) frontend.Variable { return api.Add(v, v) }\n")
	st, err := Detect(pkg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.GoModules) != 1 || st.GoModules[0].Path != "../../../go.mod" || st.GoModules[0].Gnark != "v0.12.0" {
		t.Fatalf("enclosing module: %+v", st.GoModules)
	}
	if !st.Gnark.Present || len(st.Gnark.Advisories) == 0 || !st.Library.Mode || st.Library.Gadgets != 1 {
		t.Errorf("gnark itself at v0.12.0: present %v, advisories %d, library %+v", st.Gnark.Present, len(st.Gnark.Advisories), st.Library)
	}
}
