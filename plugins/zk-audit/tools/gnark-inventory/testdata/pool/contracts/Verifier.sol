// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture: a stub with the public surface of a gnark Groth16
// verifier (no verification logic).
pragma solidity ^0.8.20;

contract Verifier {
    error PublicInputNotInField();
    error ProofInvalid();

    function verifyProof(bytes calldata proof, uint256[7] calldata input) public view {
        if (proof.length != 256) revert ProofInvalid();
        for (uint256 i = 0; i < 7; i++) {
            if (input[i] >= 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001) {
                revert PublicInputNotInField();
            }
        }
        revert ProofInvalid();
    }
}
