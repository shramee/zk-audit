package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
