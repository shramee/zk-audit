package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/sandbox"
)

// TestMain lets the test binary stand in for the tool when a command
// re-executes itself inside the sandbox (inventory type loading).
func TestMain(m *testing.M) {
	sandbox.Stage2()
	if os.Getenv(sandbox.MarkerEnv) == "1" && os.Getenv("ZK_AUDIT_SELF_EXEC") == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestArgsCommand(t *testing.T) {
	repo := t.TempDir()
	var out bytes.Buffer
	code, err := cmdArgs([]string{"--repo", repo, "--home", "/h", "--run-id", "20261029-101010", "--", "quick --no-poc"}, &out)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v: %s", code, err, out.String())
	}
	var run struct {
		Mode, Profile, Out string
		PoC                bool `json:"poc"`
	}
	if err := json.Unmarshal(out.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.Mode != "audit" || run.Profile != "quick" || run.PoC || !strings.HasSuffix(run.Out, "/h/.zk-audit/"+lastElem(repo)+"/20261029-101010") {
		t.Errorf("%+v", run)
	}
	out.Reset()
	code, err = cmdArgs([]string{"--repo", repo, "--", "--frobnicate"}, &out)
	if err != nil || code != 1 || !strings.Contains(out.String(), "unknown flag") {
		t.Fatalf("invalid: code %d err %v: %s", code, err, out.String())
	}
	if code, err := cmdArgs([]string{"--repo", repo, "--", `"unterminated`}, &out); code != 2 || err == nil {
		t.Fatalf("bad quoting must be a usage error: %d %v", code, err)
	}
}

func lastElem(p string) string {
	p = strings.TrimRight(p, "/")
	return p[strings.LastIndex(p, "/")+1:]
}

func TestProfilesCommand(t *testing.T) {
	var out bytes.Buffer
	if code, err := cmdProfiles([]string{"--profile", "quick"}, &out); code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	var p struct {
		Profile struct{ ID string }
		Lenses  []struct{ ID string }
	}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || p.Profile.ID != "quick" || len(p.Lenses) < 10 {
		t.Fatalf("%v %+v", err, p)
	}
	out.Reset()
	if code, _ := cmdProfiles([]string{"--check-docs", skillRoot}, &out); code != 0 {
		t.Fatalf("docs drift: %s", out.String())
	}
	if code, err := cmdProfiles([]string{"--profile", "huge"}, &out); code != 2 || err == nil {
		t.Fatalf("unknown profile: %d %v", code, err)
	}
}

// TestInventoryInSandbox runs type loading inside the OS sandbox, the same
// environment PoCs run in. With the fixture modules cached (make fixtures)
// it must reach types mode.
func TestInventoryInSandbox(t *testing.T) {
	if e, _ := sandbox.Detect("auto"); e == nil || e.Name == sandbox.None {
		t.Skip("no OS sandbox")
	}
	out := t.TempDir()
	var buf bytes.Buffer
	if err := cmdInventory([]string{"--repo", fixture.Dir(t, "pool"), "--out", out, "--sandbox", "on"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "load: ") {
		t.Fatalf("summary: %s", buf.String())
	}
	if os.Getenv("ZK_INVENTORY_REQUIRE_TYPES") == "1" && !strings.Contains(buf.String(), "load: types") {
		t.Fatalf("sandboxed loading did not reach types mode: %s", buf.String())
	}
	if _, err := os.Stat(out + "/coverage-ledger.json"); err != nil {
		t.Fatal(err)
	}
}
