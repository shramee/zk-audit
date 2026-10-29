package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

// TestRefuseWritesInRepo: inventory, detect and assemble refuse output
// paths inside the audited repository, also through a symlink; only
// assemble --file-output writes the report copy there.
func TestRefuseWritesInRepo(t *testing.T) {
	src := fixture.Dir(t, "pool")
	repo := t.TempDir()
	// a private copy, so the test may write the report copy into it
	if err := os.CopyFS(repo, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	alias := t.TempDir() + "/alias"
	os.Symlink(repo, alias)
	var buf bytes.Buffer
	for _, out := range []string{repo + "/audit", alias + "/audit"} {
		err := cmdInventory([]string{"--repo", repo, "--out", out, "--syntax-only"}, &buf)
		if err == nil || !strings.Contains(err.Error(), "inside the audited repository") {
			t.Errorf("inventory --out %s: %v", out, err)
		}
		if _, err := os.Stat(repo + "/audit"); err == nil {
			t.Fatalf("inventory created %s", out)
		}
	}
	if err := cmdDetect([]string{"--repo", repo, "--out", repo + "/stack.json"}, &buf); err == nil {
		t.Error("detect --out inside the repository accepted")
	}
	out := t.TempDir()
	if err := cmdInventory([]string{"--repo", repo, "--out", out, "--syntax-only"}, &buf); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(out+"/findings.json", []byte(`{"schema_version":"1","repo":"pool","run_id":"20261029-111111","profile":"quick","no_findings":true,"no_findings_reason":"refusal test","records":[]}`), 0o644)
	buf.Reset()
	code, err := cmdAssemble([]string{"--out", out, "--repo", repo, "--report", repo + "/REPORT.md"}, &buf)
	if code != 2 || err == nil || !strings.Contains(err.Error(), "inside the audited repository") {
		t.Errorf("assemble --report in repo: %d %v", code, err)
	}
	if _, err := os.Stat(repo + "/REPORT.md"); err == nil {
		t.Fatal("assemble wrote into the repository")
	}
	buf.Reset()
	code, err = cmdAssemble([]string{"--out", out, "--repo", repo, "--file-output"}, &buf)
	if code != 0 || err != nil {
		t.Fatalf("assemble --file-output: %d %v %s", code, err, buf.String())
	}
	for _, p := range []string{out + "/REPORT.md", repo + "/zk-audit-report-20261029-111111.md"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s", p)
		}
	}
}

// TestAssemblePoCManifest: assemble refuses a POC record whose file is not
// in <out>/pocs/, and writes pocs/MANIFEST.json listing every PoC file
// (including one no record references) with its hash.
func TestAssemblePoCManifest(t *testing.T) {
	out := t.TempDir()
	var buf bytes.Buffer
	if err := cmdInventory([]string{"--repo", fixture.Dir(t, "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
		t.Fatal(err)
	}
	rec := `{"schema_version":"1","repo":"pool","run_id":"20261029-121212","profile":"standard","records":[
	{"fingerprint":"VoteCircuit|tally|hint-output-unconstrained","verdict":"confirmed","title":"t","layer":"circuit","bug_class":"hint-output-unconstrained",
	 "location":{"file":"circuit/transfer.go","line":3,"scope":"X.Define"},"detected_by":["C1"],"description":"d",
	 "severity":"low","confidence":60,"evidence":"POC","proof":"p","impact":"i",
	 "gates":{"executes":"e","reachable":"r","unprivileged":"u","impact":"i"},
	 "poc":{"path":"pocs/1_poc_test.go","command":"go test","result":"demonstrated","demonstrates":"soundness","package":"circuit"}}]}`
	os.WriteFile(out+"/findings.json", []byte(rec), 0o644)
	buf.Reset()
	code, err := cmdAssemble([]string{"--out", out}, &buf)
	if code != 1 || err != nil || !strings.Contains(buf.String(), "does not exist under") {
		t.Fatalf("missing PoC file: %d %v %s", code, err, buf.String())
	}
	os.MkdirAll(out+"/pocs", 0o755)
	os.WriteFile(out+"/pocs/1_poc_test.go", []byte("package circuit\n"), 0o644)
	os.WriteFile(out+"/pocs/4_poc_test.go", []byte("package circuit\n// demoted\n"), 0o644)
	buf.Reset()
	code, err = cmdAssemble([]string{"--out", out}, &buf)
	if code != 0 || err != nil {
		t.Fatalf("assemble: %d %v %s", code, err, buf.String())
	}
	if !strings.Contains(buf.String(), "pocs/4_poc_test.go is not the poc.path of any record") {
		t.Errorf("no orphan warning: %s", buf.String())
	}
	b, err := os.ReadFile(out + "/pocs/MANIFEST.json")
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		PoCs []struct {
			File, SHA256, Fingerprint, Package string
		}
	}
	if err := json.Unmarshal(b, &man); err != nil || len(man.PoCs) != 2 {
		t.Fatalf("manifest %v: %s", err, b)
	}
	if man.PoCs[0].File != "pocs/1_poc_test.go" || man.PoCs[0].Fingerprint == "" || man.PoCs[0].Package != "circuit" || len(man.PoCs[0].SHA256) != 64 {
		t.Errorf("entry 0: %+v", man.PoCs[0])
	}
	if man.PoCs[1].File != "pocs/4_poc_test.go" || man.PoCs[1].Fingerprint != "" {
		t.Errorf("orphan entry: %+v", man.PoCs[1])
	}
}

// TestLedgerAndAgentsCommands: agents save writes the output and the index;
// ledger mark refuses to mark a unit covered by an agent with no saved
// output, then accepts it; ledger add appends a critic's unit.
func TestLedgerAndAgentsCommands(t *testing.T) {
	out := t.TempDir()
	var buf bytes.Buffer
	if err := cmdInventory([]string{"--repo", fixture.Dir(t, "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
		t.Fatal(err)
	}
	unit := "circuit:TransferCircuit|hint-soundness"
	buf.Reset()
	code, err := cmdLedger([]string{"mark", "--out", out, "--unit", unit, "--status", "covered", "--agent", "C1", "--reviewed", "circuit/transfer.go"}, &buf)
	if code != 1 || err != nil || !strings.Contains(buf.String(), "agent C1 has no saved output") {
		t.Fatalf("mark without output: %d %v %s", code, err, buf.String())
	}
	buf.Reset()
	ret := "FINDING | layer: circuit | scope: X | local: y | bug_class: z | group_key: a | b | z\nLEAD | layer: circuit\n"
	if code, err := cmdAgents([]string{"save", "--out", out, "--id", "C1"}, &buf, strings.NewReader(ret)); code != 0 || err != nil {
		t.Fatalf("agents save: %d %v %s", code, err, buf.String())
	}
	if !strings.Contains(buf.String(), "C1: done · 1 findings, 1 leads · attempt 1") {
		t.Errorf("save summary: %s", buf.String())
	}
	buf.Reset()
	if code, _ := cmdAgents([]string{"save", "--out", out, "--id", "I3", "--status", "refused"}, &buf, strings.NewReader("")); code != 1 {
		t.Errorf("refused without a reason accepted: %s", buf.String())
	}
	buf.Reset()
	if code, _ := cmdAgents([]string{"save", "--out", out, "--id", "I3", "--status", "refused", "--reason", "stopped by a safety classifier; retried once"}, &buf, strings.NewReader("")); code != 0 {
		t.Errorf("refused with a reason: %s", buf.String())
	}
	if code, _ := cmdAgents([]string{"save", "--out", out, "--id", "../x"}, &buf, strings.NewReader("x")); code != 1 {
		t.Error("path-like agent id accepted")
	}
	buf.Reset()
	code, err = cmdLedger([]string{"mark", "--out", out, "--unit", unit, "--status", "covered", "--agent", "C1", "--reviewed", "circuit/transfer.go"}, &buf)
	if code != 0 || err != nil {
		t.Fatalf("mark: %d %v %s", code, err, buf.String())
	}
	buf.Reset()
	if code, _ := cmdLedger([]string{"mark", "--out", out, "--lens", "I3", "--status", "blocked"}, &buf); code != 1 || !strings.Contains(buf.String(), "needs a reason") {
		t.Errorf("blocked without reason: %s", buf.String())
	}
	buf.Reset()
	if code, _ := cmdLedger([]string{"mark", "--out", out, "--lens", "I3", "--status", "blocked", "--reason", "I3 refused twice"}, &buf); code != 0 {
		t.Errorf("blocked with reason: %s", buf.String())
	}
	if code, _ := cmdLedger([]string{"mark", "--out", out, "--match", "NoSuchThing", "--status", "covered"}, &buf); code != 1 {
		t.Error("empty selection accepted")
	}
	buf.Reset()
	if code, _ := cmdLedger([]string{"add", "--out", out, "--kind", "circuit", "--subject", "testCircuit", "--class", "spec-invariant", "--lens", "C6", "--path", "circuit/transfer.go:9", "--notes", "coverage critic"}, &buf); code != 0 {
		t.Fatalf("add: %s", buf.String())
	}
	if code, _ := cmdLedger([]string{"add", "--out", out, "--kind", "circuit", "--subject", "testCircuit", "--class", "spec-invariant", "--lens", "C6"}, &buf); code != 1 {
		t.Error("duplicate add accepted")
	}
	led, err := os.ReadFile(out + "/coverage-ledger.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"id": "circuit:testCircuit|spec-invariant"`, `"reason": "I3 refused twice"`} {
		if !strings.Contains(string(led), want) {
			t.Errorf("ledger lacks %s", want)
		}
	}
	var vb bytes.Buffer
	if code, _ := cmdValidate([]string{"ledger", out + "/coverage-ledger.json", "--out", out}, &vb); code != 0 {
		t.Errorf("edited ledger does not validate: %s", vb.String())
	}
	idx, _ := os.ReadFile(out + "/agents/index.json")
	if !strings.Contains(string(idx), `"status": "refused"`) || !strings.Contains(string(idx), `"file": "agents/C1.md"`) {
		t.Errorf("index: %s", idx)
	}
}

// TestVerifierCommands runs the offline verifier checks on the fixture with
// a real gnark v0.14.0 verifier.
func TestVerifierCommands(t *testing.T) {
	repo := fixture.Dir(t, "sol-gnark-abi")
	var out, errb bytes.Buffer
	if code := run([]string{"verifier", "abi", "--repo", repo}, &out, &errb); code != 1 {
		t.Fatalf("verifier abi: exit %d, want 1 (mismatch): %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "selector-mismatch") || !strings.Contains(out.String(), "verifyProof(uint256[8],uint256[2])") {
		t.Errorf("verifier abi output: %s", out.String())
	}
	out.Reset()
	sol := filepath.Join(repo, "contracts", "Verifier.sol")
	if code := run([]string{"verifier", "vk", "--sol", sol}, &out, &errb); code != 0 || !strings.Contains(out.String(), "20 verifying-key constants") {
		t.Errorf("verifier vk: %d %s", code, out.String())
	}
	out.Reset()
	dep := filepath.Join(repo, "deployed", "Verifier.runtime.hex")
	if code := run([]string{"verifier", "bytecode", "--deployed", dep, "--local", dep, "--sol", sol}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "code:     equal") || !strings.Contains(out.String(), "20 of 20 VK constants") {
		t.Errorf("verifier bytecode: %d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"verifier", "diff", "--a", sol, "--b", sol}, &out, &errb); code != 0 || !strings.Contains(out.String(), "same verifier") {
		t.Errorf("verifier diff: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"verifier", "ceremony", "--repo", repo}, &out, &errb); code != 0 || !strings.Contains(out.String(), "**single-party**") {
		t.Errorf("verifier ceremony: %d %s", code, out.String())
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"verifier", "regen", "--repo", repo, "--out", filepath.Join(repo, "x"), "--vk", "k"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "inside the audited repository") {
		t.Errorf("verifier regen into the repository: %d %s", code, errb.String())
	}
}
