// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: a hand-written Groth16 verifier library with an
// assembly pairing call, used with `using ... for` and directly.
pragma solidity ^0.8.20;

library Groth16Lib {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    function verify(Proof memory proof, uint256[1] memory input) internal view returns (bool ok) {
        uint256[12] memory pairingInput;
        pairingInput[0] = proof.a[0];
        pairingInput[1] = proof.a[1];
        pairingInput[2] = input[0];
        assembly {
            ok := staticcall(gas(), 0x08, pairingInput, 384, pairingInput, 0x20)
        }
    }
}
