package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var repoRoot = filepath.Join("..", "..", "..", "..")

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
	if err := cmdInventory([]string{"--repo", filepath.Join("testdata", "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
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
	for _, want := range []string{"## Pool.withdraw → verifyProof", "| 1 | `nf` (`Nullifier`) | `nullifier` (L44)", "| 2 | `Recipient` (`Recipient`) | `uint256(uint160(recipient))` (L45) | ? | recipient |"} {
		if !strings.Contains(string(bt), want) {
			t.Errorf("binding table lacks %q:\n%s", want, bt)
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
	if err := cmdInventory([]string{"--repo", filepath.Join("testdata", "pool"), "--out", out, "--syntax-only"}, &buf); err != nil {
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
	for _, want := range []string{"Examined (covered or candidate): 0 of", "| Files reviewed | none recorded in the ledger |", "Inventory load mode: `syntax`", "gnark v0.14.0 (advisories: 3)"} {
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
