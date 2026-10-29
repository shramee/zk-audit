package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
)

// TestRunLifecycleCommands drives the commands a run uses around the
// agents, on the pool fixture, without spawning anything: args --save,
// threat-model, estimate, agents save with usage, budget check, status and
// critic-check.
func TestRunLifecycleCommands(t *testing.T) {
	src := fixture.Dir(t, "pool")
	repo := filepath.Join(t.TempDir(), "pool")
	if err := os.CopyFS(repo, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	sh := func(want int, args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != want {
			t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), errb.String())
		}
		return out.String()
	}
	var r struct {
		Out    string  `json:"out"`
		Budget float64 `json:"budget_usd"`
	}
	if err := json.Unmarshal([]byte(sh(0, "args", "--repo", repo, "--home", home, "--run-id", "20261029-130000", "--save", "--", "quick --budget 15")), &r); err != nil {
		t.Fatal(err)
	}
	out := r.Out
	if _, err := os.Stat(filepath.Join(out, "run.json")); err != nil || r.Budget != 15 {
		t.Fatalf("run.json: %v, budget %v", err, r.Budget)
	}
	// a second --save to the same directory is refused
	sh(1, "args", "--repo", repo, "--home", home, "--run-id", "20261029-130000", "--save", "--", "quick")

	if s := sh(0, "threat-model", "--repo", repo, "--out", out); !strings.Contains(s, "no zk-audit.md") {
		t.Errorf("threat-model without a file: %s", s)
	}
	os.WriteFile(filepath.Join(repo, "zk-audit.md"), []byte("## Trusted parties\n\n| Party | Trust |\n|---|---|\n| owner | sometimes |\n"), 0o644)
	if s := sh(1, "threat-model", "--repo", repo, "--out", out); !strings.Contains(s, "trust \"sometimes\"") {
		t.Errorf("bad threat model: %s", s)
	}
	os.WriteFile(filepath.Join(repo, "zk-audit.md"), []byte("## Trusted parties\n\n| Party | Trust |\n|---|---|\n| owner | trusted |\n"), 0o644)
	sh(0, "threat-model", "--repo", repo, "--out", out)
	sh(0, "validate", "threat-model", filepath.Join(out, "threat-model.json"))
	sh(2, "threat-model", "--repo", repo, "--out", filepath.Join(repo, "x"))

	sh(0, "inventory", "--repo", repo, "--out", out, "--syntax-only")
	if s := sh(0, "estimate", "--out", out, "--profile", "quick"); !strings.Contains(s, "| quick |") || !strings.Contains(s, "Calibration: ") {
		t.Errorf("estimate: %s", s)
	}
	sh(0, "bundle", "--out", out, "--skill", filepath.Join("..", ".."), "--profile", "quick")
	raw := filepath.Join(t.TempDir(), "C1.md")
	os.WriteFile(raw, []byte("FINDING | x\nlocation: circuit/transfer.go:61\n"), 0o644)
	sh(0, "agents", "save", "--out", out, "--id", "C1", "--from", raw, "--tokens", "51000", "--tool-uses", "12", "--duration-ms", "90000")
	sh(0, "agents", "save", "--out", out, "--id", "I1", "--status", "refused", "--reason", "safety classifier")
	sh(0, "budget", "record", "--out", out, "--id", "refuter-1", "--role", "refuter")
	var d struct {
		Stop   bool    `json:"stop"`
		Budget float64 `json:"budget_usd"`
	}
	json.Unmarshal([]byte(sh(0, "budget", "check", "--out", out, "--before", "hunt pass 1", "--hunter", "4")), &d)
	if d.Stop || d.Budget != 15 {
		t.Errorf("small wave: %+v", d)
	}
	json.Unmarshal([]byte(sh(0, "budget", "check", "--out", out, "--before", "hunt pass 2", "--hunter", "40")), &d)
	if !d.Stop {
		t.Errorf("a 40-hunter wave fits 15 USD: %+v", d)
	}
	if s := sh(0, "budget", "show", "--out", out); !strings.Contains(s, "stopped:") {
		t.Errorf("budget show: %s", s)
	}
	st := sh(0, "status", "--out", out)
	for _, want := range []string{"run 20261029-130000 · profile quick", "| 2 Hunt | hunt | partial |", "budget ceiling"} {
		if !strings.Contains(st, want) {
			t.Errorf("status lacks %q:\n%s", want, st)
		}
	}
	if s := sh(0, "critic-check", "--out", out); !strings.Contains(s, "missing units from 1 agent outputs") {
		t.Errorf("critic-check: %s", s)
	}
	if s := sh(1, "critic-check", "--out", out, "--verify"); !strings.Contains(s, "FAIL critic-check") {
		t.Errorf("critic-check --verify: %s", s)
	}
	// resume finds the run by id and keeps its budget unless raised
	var res struct {
		Resume bool    `json:"resume"`
		Budget float64 `json:"budget_usd"`
		Out    string  `json:"out"`
	}
	json.Unmarshal([]byte(sh(0, "args", "--repo", repo, "--home", home, "--save", "--", "resume 20261029-130000 --budget 40")), &res)
	if !res.Resume || res.Budget != 40 || res.Out != out {
		t.Errorf("resume: %+v", res)
	}
	if st := sh(0, "status", "--out", out); strings.Contains(st, "budget ceiling") {
		t.Errorf("a raised budget still shows the stop:\n%s", st)
	}
	json.Unmarshal([]byte(sh(0, "budget", "check", "--out", out, "--before", "hunt pass 2", "--hunter", "10")), &d)
	if d.Stop || d.Budget != 40 {
		t.Errorf("after resume --budget 40: %+v", d)
	}
}
