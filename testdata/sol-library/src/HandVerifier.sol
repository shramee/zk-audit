// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: a hand-written verifier contract inherited by
// its caller, which calls verifyProof without a receiver.
pragma solidity ^0.8.20;

contract HandVerifier {
    function verifyProof(uint256[8] memory proof, uint256[1] memory input) public view returns (bool) {
        uint256[2] memory p;
        bool success;
        assembly {
            success := staticcall(gas(), 7, proof, 96, p, 64)
        }
        if (!success) return false;
        return p[0] == input[0];
    }
}
