package verifier

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/sandbox"
)

// TestMain lets the test binary serve as the sandbox's second stage.
func TestMain(m *testing.M) {
	sandbox.Stage2()
	os.Exit(m.Run())
}

// gnarkCached skips (or, with ZK_INVENTORY_REQUIRE_TYPES=1 as in make
// test-types, fails) when gnark v0.14.0 is not in the module cache.
func gnarkCached(t *testing.T) {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	cache := strings.TrimSpace(string(out))
	if err == nil && cache != "" {
		if _, err := os.Stat(filepath.Join(cache, "github.com", "consensys", "gnark@v0.14.0", "go.mod")); err == nil {
			return
		}
	}
	msg := "gnark v0.14.0 is not in the module cache; run `make fixtures` (network) to test verifier regeneration"
	if os.Getenv("ZK_INVENTORY_REQUIRE_TYPES") != "" {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

// Regeneration runs the fixture's own gnark v0.14.0 in the sandbox: from the
// committed vk file it reproduces the committed verifier exactly; from the
// repository's export program (a fresh single-party setup) and from the
// circuit type it reproduces the structure with another VK.
func TestRegen(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles gnark")
	}
	gnarkCached(t)
	repo := fixture.Dir(t, "sol-gnark-abi")
	committed, err := os.ReadFile(filepath.Join(repo, "contracts", "Verifier.sol"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		opt      RegenOptions
		vkEqual  bool
		wantMode string
	}{
		{"vk", RegenOptions{VK: filepath.Join(repo, "keys", "verifier.vk")}, true, "vk"},
		{"main", RegenOptions{Main: "cmd/export"}, false, "main"},
		{"circuit", RegenOptions{Circuit: "circuit.RedeemCircuit"}, false, "circuit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			opt := c.opt
			opt.Repo, opt.Out = repo, t.TempDir()
			res, err := Regen(opt)
			if err != nil {
				t.Fatalf("regen: %v", err)
			}
			if res.Mode != c.wantMode || res.Gnark != "v0.14.0" || len(res.Verifiers) != 1 {
				t.Fatalf("result: %+v", res)
			}
			got, err := os.ReadFile(res.Verifiers[0])
			if err != nil {
				t.Fatal(err)
			}
			d := Diff("committed", string(committed), "regenerated", string(got))
			if !d.Structure.Equal {
				t.Errorf("structure differs: %v", d.Structure.Differences)
			}
			if d.VK.Equal != c.vkEqual {
				t.Errorf("VK equal %v, want %v (%s)", d.VK.Equal, c.vkEqual, d.Summary)
			}
			if c.vkEqual && string(got) != string(committed) {
				t.Error("the vk file's export is not byte-identical to the committed verifier")
			}
		})
	}
	// the original repository is untouched
	if _, err := os.Stat(filepath.Join(repo, "cmd", "export", "Verifier.sol")); err == nil {
		t.Error("regen wrote into the repository")
	}
	if _, err := os.Stat(filepath.Join(repo, "zkaudit_regen")); err == nil {
		t.Error("regen wrote its program into the repository")
	}
}
