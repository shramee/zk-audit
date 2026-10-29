package solidity

import (
	"strings"
	"testing"
)

const src = `
pragma solidity ^0.8.0;
/* contract Fake { function verifyProof() } */
interface IPlonk { function Verify(bytes calldata p, uint256[] calldata pub) external view returns (bool); }
contract Mixer {
    IPlonk verifier; // the verifier
    mapping(bytes32 => bool) public spentProofs;
    mapping(uint256 => uint256) private roots;
    uint256 public nonce = 1;

    function deposit(uint256 c) external { roots[c] = block.number; nonce++; }

    function spend(bytes calldata proof, uint256 root, uint256 nf) external {
        uint256[] memory pub = new uint256[](3);
        pub[0] = root;
        pub[1] = nf;
        pub[2] = uint256(keccak256(abi.encode(msg.sender, block.chainid))) >> 8;
        require(verifier.Verify(proof, pub), "bad proof");
        spentProofs[keccak256(proof)] = true;
    }

    function spendUnchecked(bytes calldata proof, uint256 a, uint256 b) external {
        verifier.Verify(proof, [a, b]);
        delete roots[a];
    }
}
`

func TestScan(t *testing.T) {
	r := ScanSource("Mixer.sol", src)
	if len(r.Verifiers) != 0 {
		t.Errorf("Mixer is not a verifier: %+v", r.Verifiers)
	}
	if len(r.VerifyCalls) != 2 {
		t.Fatalf("verify calls: %+v", r.VerifyCalls)
	}
	if !r.VerifyCalls[0].ResultUsed || r.VerifyCalls[1].ResultUsed {
		t.Errorf("result used: %v %v", r.VerifyCalls[0].ResultUsed, r.VerifyCalls[1].ResultUsed)
	}
	var spend, inline []string
	for _, a := range r.InputAssigns {
		switch a.Function {
		case "spend":
			spend = append(spend, a.Expr)
		case "spendUnchecked":
			inline = append(inline, a.Array+"="+a.Expr)
		}
	}
	if len(spend) != 3 || !strings.Contains(spend[2], "keccak256") {
		t.Errorf("spend inputs: %v", spend)
	}
	if len(inline) != 2 || inline[0] != "(inline)=a" {
		t.Errorf("inline inputs: %v", inline)
	}
	if b := MentionsBinding(spend[2]); len(b) != 2 {
		t.Errorf("binding mentions: %v", b)
	}
	kinds := map[string]string{}
	for _, s := range r.StateVars {
		kinds[s.Name] = s.Kind
	}
	for name, kind := range map[string]string{"verifier": "verifier", "spentProofs": "nullifier", "roots": "root", "nonce": "nonce"} {
		if kinds[name] != kind {
			t.Errorf("%s: kind %q want %q (all %v)", name, kinds[name], kind, kinds)
		}
	}
	ops := map[string]bool{}
	for _, a := range r.StateAccess {
		ops[a.Name+":"+a.Op] = true
	}
	for _, k := range []string{"roots:write", "nonce:write", "spentProofs:write", "roots:delete"} {
		if !ops[k] {
			t.Errorf("missing access %s in %v", k, ops)
		}
	}
}

func TestStripComments(t *testing.T) {
	in := "a // x\n/* y\nz */ b \"//not\""
	out := stripComments(in)
	if strings.Count(out, "\n") != strings.Count(in, "\n") || !strings.Contains(out, "\"//not\"") || strings.Contains(out, "x") || strings.Contains(out, "y") {
		t.Fatalf("stripComments: %q", out)
	}
}
