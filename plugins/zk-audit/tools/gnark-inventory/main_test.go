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
