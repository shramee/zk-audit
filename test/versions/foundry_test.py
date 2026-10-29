"""Writes a Foundry test for a gnark-exported Groth16 verifier.

Usage: foundry_test.py Verifier.sol proof.txt Version.t.sol

proof.txt holds the eight proof words (Ar, Bs, Krs as gnark's raw
encoding orders them) and the public input. The ABI of the exported
verifyProof differs between gnark releases; the script reads it from the
contract, writes a test for it and prints the ABI it found. Exit 1 when the
ABI is not one it knows.
"""
import re
import sys

sol, proof_path, test_path = sys.argv[1:4]
src = open(sol).read()
words = [w.strip() for w in open(proof_path) if w.strip()]
proof, pub = words[:8], words[8]
m = re.search(r"pragma solidity ([^;]+);", src)
pragma = m.group(1) if m else "^0.8.0"
contract = re.search(r"contract (\w+)", src).group(1)

if re.search(r"function verifyProof\(\s*uint256\[8\] calldata proof,\s*uint256\[1\] calldata input", src):
    abi = "verifyProof(uint256[8] proof, uint256[1] input), reverts on an invalid proof"
    call_ok = "v.verifyProof(p, [uint256(%s)]);" % pub
    call_bad = "try v.verifyProof(p, [uint256(%s) + 1]) { revert(\"wrong input accepted\"); } catch {}" % pub
elif re.search(r"function verifyProof\(\s*uint256\[2\] memory a,\s*uint256\[2\]\[2\] memory b,\s*uint256\[2\] memory c,\s*uint256\[1\] (?:memory|calldata) input", src):
    abi = "verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[1] input) returns (bool)"
    split = "[p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]]"
    call_ok = "require(v.verifyProof(%s, [uint256(%s)]), \"valid proof rejected\");" % (split, pub)
    call_bad = "bool ok; try v.verifyProof(%s, [uint256(%s) + 1]) returns (bool r) { ok = r; } catch {} require(!ok, \"wrong input accepted\");" % (split, pub)
elif re.search(r"function verifyProof\(\s*bytes calldata proof,\s*uint256\[1\] calldata input", src):
    abi = "verifyProof(bytes proof, uint256[1] input), reverts on an invalid proof; proof = the 8 words packed (256 bytes without commitments)"
    call_ok = "v.verifyProof(abi.encodePacked(p), [uint256(%s)]);" % pub
    call_bad = "try v.verifyProof(abi.encodePacked(p), [uint256(%s) + 1]) { revert(\"wrong input accepted\"); } catch {}" % pub
else:
    sig = re.search(r"function verifyProof\([^)]*\)", src)
    print("unknown verifyProof ABI: " + (" ".join(sig.group(0).split()) if sig else "none"))
    sys.exit(1)

words_sol = ";\n        ".join("p[%d] = %s" % (i, w) for i, w in enumerate(proof))
open(test_path, "w").write("""// SPDX-License-Identifier: UNLICENSED
pragma solidity %(pragma)s;

import {%(contract)s} from "../src/Verifier.sol";

contract PoC_VersionMatrix {
    %(contract)s v;

    function setUp() public {
        v = new %(contract)s();
    }

    function proof() internal pure returns (uint256[8] memory p) {
        %(words)s;
    }

    function testHonestProofVerifies() public view {
        uint256[8] memory p = proof();
        %(ok)s
    }

    function testWrongInputRejected() public view {
        uint256[8] memory p = proof();
        %(bad)s
    }
}
""" % {"pragma": pragma, "contract": contract, "words": words_sol, "ok": call_ok, "bad": call_bad})
print(abi)
