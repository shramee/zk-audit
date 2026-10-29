package main

import (
	"bytes"
	"encoding/json"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository root, six levels up:
// gnark-inventory -> tools -> skills/zk-audit -> skills -> plugins/zk-audit -> plugins -> root.
var repoRoot = filepath.Join("..", "..", "..", "..", "..", "..")

// skillRoot is the self-contained skill folder that holds this tool.
var skillRoot = filepath.Join("..", "..")

func TestPluginMetadata(t *testing.T) {
	var mkt struct {
		Name    string `json:"name"`
		Plugins []struct {
			Name, Version, Description, Source string
		} `json:"plugins"`
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, ".claude-plugin", "marketplace.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &mkt); err != nil {
		t.Fatal(err)
	}
	var plug struct{ Name, Version, Description string }
	b, err = os.ReadFile(filepath.Join(repoRoot, "plugins", "zk-audit", ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &plug); err != nil {
		t.Fatal(err)
	}
	if mkt.Name != "zk-audit" || len(mkt.Plugins) != 1 {
		t.Fatalf("marketplace: %+v", mkt)
	}
	p := mkt.Plugins[0]
	if p.Name != plug.Name || p.Version != plug.Version || p.Description != plug.Description || p.Source != "./plugins/"+plug.Name {
		t.Errorf("marketplace entry %+v does not match plugin.json %+v", p, plug)
	}
	if plug.Version != Version {
		t.Errorf("plugin version %s != tool Version %s", plug.Version, Version)
	}
	v, err := os.ReadFile(filepath.Join(skillRoot, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(v)); s != Version {
		t.Errorf("skills/zk-audit/VERSION %q != tool Version %s", s, Version)
	}
}

// TestCheckVersionScript runs scripts/check-version against local files: it
// warns only when the published version is higher, is silent otherwise, and
// always exits 0.
func TestCheckVersionScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	script, err := filepath.Abs(filepath.Join(skillRoot, "scripts", "check-version"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parts := strings.Split(Version, ".")
	cases := []struct {
		name, remote string
		warn         bool
	}{
		{"newer", "999.0.0", true},
		{"newer-patch", Version + ".1", true},
		{"same", Version, false},
		{"older", "0.0.0", false},
		{"junk", "<html>Not Found</html>", false},
		{"missing", "", false},
	}
	if len(parts) == 3 && parts[0] != "0" {
		cases = append(cases, struct {
			name, remote string
			warn         bool
		}{"older-major", "0." + parts[1] + "." + parts[2], false})
	}
	for _, c := range cases {
		url := "file://" + filepath.Join(dir, c.name)
		if c.name != "missing" {
			if err := os.WriteFile(filepath.Join(dir, c.name), []byte(c.remote+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("bash", script)
		cmd.Env = append(os.Environ(), "ZK_AUDIT_VERSION_URL="+url, "ZK_AUDIT_NO_UPDATE_CHECK=")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: exit %v (want 0): %s", c.name, err, out)
		}
		if got := strings.Contains(string(out), "older than the published"); got != c.warn {
			t.Errorf("%s: warn=%v, want %v: %q", c.name, got, c.warn, out)
		}
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "ZK_AUDIT_VERSION_URL=file://"+filepath.Join(dir, "newer"), "ZK_AUDIT_NO_UPDATE_CHECK=1")
	if out, err := cmd.CombinedOutput(); err != nil || len(out) != 0 {
		t.Errorf("opt-out: err %v out %q", err, out)
	}
}

// TestAllJSONParses parses every JSON file of the plugin and marketplace.
func TestAllJSONParses(t *testing.T) {
	n := 0
	for _, dir := range []string{filepath.Join(repoRoot, ".claude-plugin"), filepath.Join(repoRoot, "plugins", "zk-audit")} {
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && (info.Name() == "vendor" || info.Name() == "testdata") {
				return filepath.SkipDir
			}
			if !strings.HasSuffix(p, ".json") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Errorf("%s: %v", p, err)
			}
			n++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 5 {
		t.Fatalf("only %d JSON files inspected", n)
	}
}

func TestValidateExitCodes(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"schema_version":"1","repo":"r","generated_by":"t","units":[]}`), 0o644)
	var out bytes.Buffer
	code, err := cmdValidate([]string{"ledger", bad}, &out)
	if err != nil || code != 1 || !strings.Contains(out.String(), "zero units") {
		t.Fatalf("empty ledger: code %d err %v out %s", code, err, out.String())
	}
	if code, err := cmdValidate([]string{"nope", bad}, &out); err == nil || code != 2 {
		t.Fatalf("unknown kind should be a usage error, got %d %v", code, err)
	}
}

func TestInventoryCommand(t *testing.T) {
	out := t.TempDir()
	var buf bytes.Buffer
	if err := cmdInventory([]string{"--repo", fixture.Dir(t, "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"inventory.json", "inventory.md", "binding-table.md", "coverage-ledger.json", "stack.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	for _, kind := range []string{"ledger", "stack"} {
		name := map[string]string{"ledger": "coverage-ledger.json", "stack": "stack.json"}[kind]
		var vb bytes.Buffer
		code, err := cmdValidate([]string{kind, filepath.Join(out, name)}, &vb)
		if err != nil || code != 0 {
			t.Errorf("%s does not validate: %s", name, vb.String())
		}
	}
	bt, _ := os.ReadFile(filepath.Join(out, "binding-table.md"))
	for _, want := range []string{"## Pool.withdraw → IVerifier.verifyProof", "Verifier: Verifier (contracts/Verifier.sol:6, matched by selector", "| 1 | `nf` (`Nullifier`) | `nullifier` (L44)", "| 2 | `Recipient` (`Recipient`) | `uint256(uint160(recipient))` (L45) | ? | recipient |"} {
		if !strings.Contains(string(bt), want) {
			t.Errorf("binding table lacks %q:\n%s", want, bt)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "inventory.md"))
	for _, want := range []string{"### Privileged functions", "| `Pool.setVerifier` | contracts/Pool.sol:20 | `require(msg.sender == owner, \"owner\")` | owner | verifier | verifier |", "| `Pool.addRoot` | contracts/Pool.sol:25 |", "| `Pool.owner` | owner |"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("inventory.md lacks %q", want)
		}
	}
	if !strings.Contains(buf.String(), "circuits: 3") {
		t.Errorf("summary line: %s", buf.String())
	}
}

// TestAssembleCommand runs inventory → findings → assemble, and checks that
// invalid input writes no report.
func TestAssembleCommand(t *testing.T) {
	out := t.TempDir()
	var buf bytes.Buffer
	if err := cmdInventory([]string{"--repo", fixture.Dir(t, "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
		t.Fatal(err)
	}
	// The seeded ledger has only planned units; findings say nothing was found.
	findings := `{"schema_version":"1","repo":"pool","run_id":"20261027-101500","profile":"quick","no_findings":true,"no_findings_reason":"recon only","records":[]}`
	if err := os.WriteFile(filepath.Join(out, "findings.json"), []byte(findings), 0o644); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	code, err := cmdAssemble([]string{"--out", out}, &buf)
	if err != nil || code != 0 {
		t.Fatalf("assemble: code %d err %v out %s", code, err, buf.String())
	}
	rep, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Examined (covered): 0 of", "| Files reviewed | none recorded in the ledger |", "Inventory load mode: `syntax`", "gnark v0.14.0 (advisories: 3) · gnark-crypto v0.19.0 (advisories: 1)"} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("REPORT.md lacks %q", want)
		}
	}
	if !strings.Contains(buf.String(), "is still planned") {
		t.Errorf("expected warnings for planned units: %s", buf.String())
	}

	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "findings.json"), []byte(`{"schema_version":"1","repo":"pool","run_id":"x","profile":"quick","records":[]}`), 0o644)
	os.WriteFile(filepath.Join(bad, "coverage-ledger.json"), []byte(`{"schema_version":"1","repo":"r","generated_by":"t","units":[]}`), 0o644)
	buf.Reset()
	code, err = cmdAssemble([]string{"--out", bad}, &buf)
	if err != nil || code != 1 || !strings.Contains(buf.String(), "REPORT.md not written") {
		t.Fatalf("invalid input: code %d err %v out %s", code, err, buf.String())
	}
	if _, err := os.Stat(filepath.Join(bad, "REPORT.md")); err == nil {
		t.Fatal("REPORT.md written for invalid input")
	}
	if code, err := cmdAssemble(nil, &buf); err == nil || code != 2 {
		t.Fatalf("missing --out should be a usage error, got %d %v", code, err)
	}
}
