package solidity

import (
	"sort"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
)

func callsBy(r *Result) map[string]VerifyCall {
	out := map[string]VerifyCall{}
	for _, c := range r.VerifyCalls {
		k := c.Contract + "." + c.Function
		if _, dup := out[k]; dup {
			k += "#2"
		}
		out[k] = c
	}
	return out
}

func refs(vs []VerifierRef) string {
	var s []string
	for _, v := range vs {
		s = append(s, v.Contract+":"+v.Match)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// Inheritance: the call in an abstract base, a modifier declared in a base,
// an owner gate from a lib/ base reached through a foundry.toml remapping,
// a setter of state declared in the base.
func TestScanRepoInheritance(t *testing.T) {
	root := fixture.Dir(t, "sol-inherit")
	r, err := ScanRepo(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Files {
		if strings.HasPrefix(f, "lib/") {
			t.Errorf("lib/ file %s scanned as in scope", f)
		}
	}
	imps := map[string]Import{}
	for _, i := range r.Imports {
		imps[i.Path] = i
	}
	if i := imps["@fakeoz/access/Ownable.sol"]; i.Via != "remapping" || i.Resolved != "lib/fakeoz/src/access/Ownable.sol" {
		t.Errorf("remapped import: %+v", i)
	}
	if i := imps["@unknown/Missing.sol"]; i.Via != "unresolved" {
		t.Errorf("missing import: %+v", i)
	}
	if c, ok := r.ContractByName("Ownable"); !ok || !c.Peripheral {
		t.Errorf("Ownable should be listed as a peripheral contract: %+v", c)
	}
	calls := callsBy(r)
	vc, ok := calls["BaseVault._checkAndSpend"]
	if !ok {
		t.Fatalf("verify call in the base not found: %v", calls)
	}
	if vc.Via != "external" || vc.ReceiverType != "IVerifier" || vc.Target == nil || vc.Target.Signature != "verifyProof(uint256[8],uint256[2])" {
		t.Errorf("base call typing: via %s type %s target %+v", vc.Via, vc.ReceiverType, vc.Target)
	}
	if strings.Join(vc.InheritedBy, ",") != "Vault" {
		t.Errorf("inherited by %v, want Vault", vc.InheritedBy)
	}
	priv := map[string]Privileged{}
	for _, p := range r.Privileged {
		priv[p.Contract+"."+p.Function] = p
	}
	if p := priv["Vault.setVerifier"]; p.Party != "owner" || strings.Join(p.Powers, ",") != "verifier" {
		t.Errorf("setVerifier (owner gate from lib/ base, state from local base): %+v", p)
	}
	if p := priv["Vault.setFee"]; p.Party != "relayer" {
		t.Errorf("setFee (modifier declared in the base): %+v", p)
	}
	roles := map[string]bool{}
	for _, ro := range r.Roles {
		roles[ro.Contract+"."+ro.Name] = true
	}
	if !roles["Vault.owner"] {
		t.Errorf("Vault.owner role from the lib/ base missing: %v", roles)
	}
	eps := map[string]EntryPoint{}
	for _, e := range r.EntryPoints {
		eps[e.Contract+"."+e.Function] = e
	}
	if e := eps["Vault.redeem"]; strings.Join(e.Effects, ",") != "eth-out" || e.Party != "anyone" {
		t.Errorf("redeem entry point: %+v", e)
	}
	if _, ok := eps["BaseVault._checkAndSpend"]; ok {
		t.Error("internal function listed as an entry point")
	}
}

// Several verifiers, interfaces with overloads, a registry mapping and
// low-level staticcalls built three ways.
func TestScanRepoMultipleVerifiers(t *testing.T) {
	root := fixture.Dir(t, "sol-multi")
	r, err := ScanRepo(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, v := range r.Verifiers {
		kinds[v.Contract] = v.Kind + "/" + v.Generator
	}
	if kinds["DepositVerifier"] != "gnark-groth16/gnark" || kinds["ExitVerifier"] != "gnark-plonk/gnark" || len(kinds) != 2 {
		t.Fatalf("verifiers: %v", kinds)
	}
	calls := callsBy(r)
	want := map[string]struct{ via, sig, refs string }{
		"Gateway.deposit":    {"external", "verifyProof(uint256[8],uint256[2])", "DepositVerifier:selector"},
		"Gateway.exit":       {"external", "Verify(bytes,uint256[])", "ExitVerifier:selector"},
		"Gateway.exitVia":    {"external", "Verify(bytes,uint256[])", "ExitVerifier:selector"},
		"Gateway.depositRaw": {"staticcall", "verifyProof(uint256[8],uint256[2])", "DepositVerifier:selector"},
		"Gateway.depositSig": {"staticcall", "verifyProof(bytes,uint256[2])", "DepositVerifier:name-only"},
		"Gateway.exitCall":   {"staticcall", "Verify(bytes,uint256[])", "ExitVerifier:selector"},
	}
	for k, w := range want {
		vc, ok := calls[k]
		if !ok {
			t.Errorf("%s: no call found (have %v)", k, keysOf(calls))
			continue
		}
		sig := ""
		if vc.Target != nil {
			sig = vc.Target.Signature
		}
		if vc.LowLevel != nil {
			sig = vc.LowLevel.Signature
		}
		if vc.Via != w.via || sig != w.sig || refs(vc.Verifiers) != w.refs {
			t.Errorf("%s: via %s sig %s verifiers %s; want %s %s %s", k, vc.Via, sig, refs(vc.Verifiers), w.via, w.sig, w.refs)
		}
	}
	if vc := calls["Gateway.deposit"]; vc.Target == nil || vc.Target.Overloads != 1 {
		t.Errorf("overload count: %+v", vc.Target)
	}
	if ll := calls["Gateway.depositRaw"].LowLevel; ll == nil || ll.SuccessChecked || ll.Selector != "0x"+strings.TrimPrefix(calls["Gateway.deposit"].Target.Selector, "0x") {
		t.Errorf("depositRaw low-level: %+v", ll)
	}
	if ll := calls["Gateway.depositSig"].LowLevel; ll == nil || !ll.SuccessChecked || !ll.DecodesBool {
		t.Errorf("depositSig low-level: %+v", ll)
	}
	if ll := calls["Gateway.exitCall"].LowLevel; ll == nil || !ll.SuccessChecked || ll.Encoding != "encodeCall" {
		t.Errorf("exitCall low-level: %+v", ll)
	}
	if calls["Gateway.depositRaw"].ResultUsed {
		t.Error("depositRaw: unchecked success reported as used")
	}
	// the inline array of deposit and the staticcall input both reach the
	// public-input table
	var inline []string
	for _, a := range r.InputAssigns {
		if a.Function == "deposit" {
			inline = append(inline, a.Expr)
		}
	}
	if strings.Join(inline, ",") != "note,amount" {
		t.Errorf("deposit inputs %v", inline)
	}
}

// Library verifiers, `using ... for`, an inherited verifier called without
// a receiver, and a non-verifier library named verify.
func TestScanRepoLibraries(t *testing.T) {
	root := fixture.Dir(t, "sol-library")
	r, err := ScanRepo(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	gens := map[string]string{}
	for _, v := range r.Verifiers {
		gens[v.Contract] = v.Kind + "/" + v.Generator
		if v.Contract == "Groth16Lib" && !v.Library {
			t.Error("Groth16Lib not marked as a library")
		}
	}
	if gens["Groth16Lib"] != "custom/hand-written" || gens["HandVerifier"] != "custom/hand-written" || len(gens) != 2 {
		t.Fatalf("verifiers: %v", gens)
	}
	if len(r.NonGnarkVerifiers()) != 2 {
		t.Errorf("non-gnark verifiers: %v", r.NonGnarkVerifiers())
	}
	calls := callsBy(r)
	for k, w := range map[string]struct{ via, refs string }{
		"Claims.claim":          {"using", "Groth16Lib:direct"},
		"Claims.claimDirect":    {"library", "Groth16Lib:direct"},
		"Claims.claimInherited": {"inherited", "HandVerifier:inherited-call"},
	} {
		vc, ok := calls[k]
		if !ok {
			t.Errorf("%s: not found (have %v)", k, keysOf(calls))
			continue
		}
		if vc.Via != w.via || refs(vc.Verifiers) != w.refs {
			t.Errorf("%s: via %s verifiers %s; want %s %s", k, vc.Via, refs(vc.Verifiers), w.via, w.refs)
		}
	}
	if _, ok := calls["Claims.claimListed"]; ok {
		t.Error("MerkleProof.verify reported as a proof verification")
	}
}

func keysOf(m map[string]VerifyCall) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
