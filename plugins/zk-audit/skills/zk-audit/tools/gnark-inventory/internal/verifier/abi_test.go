package verifier

import (
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

func TestTemplateFor(t *testing.T) {
	for _, c := range []struct{ backend, version, want string }{
		{"groth16", "v0.8.1", "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])"},
		{"groth16", "v0.9.1", "verifyProof(uint256[8],uint256[3])"},
		{"groth16", "v0.14.0", "verifyProof(uint256[8],uint256[3])"},
		{"groth16", "v0.14.1-0.20250101000000-abcdefabcdef", "verifyProof(uint256[8],uint256[3])"},
		{"groth16", "v0.15.0", "verifyProof(bytes,uint256[3])"},
		{"groth16", "v0.16.4", "verifyProof(bytes,uint256[3])"},
		{"plonk", "v0.8.0", "verify_serialized_proof(uint256[],uint256[])"},
		{"plonk", "v0.16.4", "Verify(bytes,uint256[])"},
	} {
		tm, ok := TemplateFor(c.backend, c.version)
		if !ok {
			t.Errorf("%s %s: no template", c.backend, c.version)
			continue
		}
		if got := tm.Expect(3, 0)[0].Signature; got != c.want {
			t.Errorf("%s %s: %s, want %s", c.backend, c.version, got, c.want)
		}
	}
	tm, _ := TemplateFor("groth16", "v0.12.0")
	var sigs []string
	for _, e := range tm.Expect(2, 1) {
		sigs = append(sigs, e.Signature)
	}
	if sigs[0] != "verifyProof(uint256[8],uint256[2],uint256[2],uint256[2])" {
		t.Errorf("commitment variant: %v", sigs)
	}
	if e := tm.Expect(2, 0)[0]; e.Selector == "" || len(e.Returns) != 0 {
		t.Errorf("selector or returns: %+v", e)
	}
}

func check(t *testing.T, r *ABIReport, caller string) ABICheck {
	t.Helper()
	for _, c := range r.Calls {
		if c.Caller == caller {
			return c
		}
	}
	t.Fatalf("no ABI check for %s in %+v", caller, r.Calls)
	return ABICheck{}
}

func statuses(c ABICheck) string {
	var s []string
	for _, a := range c.Against {
		s = append(s, a.Against+":"+a.Status)
	}
	return strings.Join(s, ",")
}

// The measured finding: a caller's own IVerifier against the verifier gnark
// v0.14.0 really exported.
func TestCheckABIRealGnarkVerifier(t *testing.T) {
	res, err := solidity.ScanRepo(fixture.Dir(t, "sol-gnark-abi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verifiers) != 1 || res.Verifiers[0].NbPublic != 2 || !strings.Contains(res.Verifiers[0].Template, "v0.9.0 to v0.14.x") {
		t.Fatalf("verifier: %+v", res.Verifiers)
	}
	r := CheckABI(res, Gnark{Versions: []string{"v0.14.0"}, Backends: []string{"groth16"}, PublicCounts: []int{2}})
	c := check(t, r, "Redeemer.redeem")
	if c.Status != "mismatch" || statuses(c) != "repo-verifier:selector-mismatch,gnark-template:selector-mismatch" {
		t.Fatalf("redeem: %s %s", c.Status, statuses(c))
	}
	if c.Signature != "verifyProof(bytes,uint256[2])" || c.Against[1].Signature != "verifyProof(uint256[8],uint256[2])" {
		t.Errorf("signatures: caller %s, gnark %s", c.Signature, c.Against[1].Signature)
	}
	if !strings.Contains(c.Against[1].Detail, "reverts") {
		t.Errorf("detail: %s", c.Against[1].Detail)
	}
	if len(r.Verifiers) != 1 || r.Verifiers[0].Status != "match" {
		t.Errorf("verifier vs v0.14.0 template: %+v", r.Verifiers)
	}
	// with gnark v0.15+, the selector matches but the bool decode still reverts
	r = CheckABI(res, Gnark{Versions: []string{"v0.16.4"}, Backends: []string{"groth16"}})
	c = check(t, r, "Redeemer.redeem")
	if a := c.Against[len(c.Against)-1]; a.Status != "return-mismatch" || !strings.Contains(a.Detail, "every call reverts") {
		t.Errorf("v0.16.4 template: %+v", a)
	}
	if r.Verifiers[0].Status != "mismatch" {
		t.Errorf("a v0.14 verifier against v0.16.4: %+v", r.Verifiers[0])
	}
}

// The pool fixture: a v0.15-style verifier stub in a v0.14.0 module.
func TestCheckABIStaleVerifier(t *testing.T) {
	res, err := solidity.ScanRepo(fixture.Dir(t, "pool"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := CheckABI(res, Gnark{Versions: []string{"v0.14.0"}, Backends: []string{"groth16"}})
	c := check(t, r, "Pool.withdraw")
	if statuses(c) != "repo-verifier:match,gnark-template:selector-mismatch" {
		t.Errorf("withdraw: %s", statuses(c))
	}
	if r.Verifiers[0].Status != "mismatch" || !strings.Contains(r.Verifiers[0].Detail, "verifyProof(uint256[8],uint256[7])") {
		t.Errorf("verifier: %+v", r.Verifiers[0])
	}
}

func TestCheckABIRepoOnly(t *testing.T) {
	res, err := solidity.ScanRepo(fixture.Dir(t, "sol-multi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := CheckABI(res, Gnark{})
	for caller, want := range map[string]string{
		"Gateway.deposit":    "repo-verifier:match",
		"Gateway.exit":       "repo-verifier:match",
		"Gateway.exitVia":    "repo-verifier:bool-ignored",
		"Gateway.depositRaw": "repo-verifier:bool-ignored",
		"Gateway.depositSig": "repo-verifier:selector-mismatch",
		"Gateway.exitCall":   "repo-verifier:bool-ignored",
	} {
		if got := statuses(check(t, r, caller)); got != want {
			t.Errorf("%s: %s, want %s", caller, got, want)
		}
	}
}
