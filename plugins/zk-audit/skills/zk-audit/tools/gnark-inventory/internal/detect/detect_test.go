package detect

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

func TestDetectPool(t *testing.T) {
	st, err := Detect(filepath.Join("..", "..", "testdata", "pool"), "test")
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
