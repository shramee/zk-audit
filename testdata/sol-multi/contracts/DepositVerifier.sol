// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: the public surface of a gnark Groth16 verifier
// (template v0.9.0 to v0.14.x), no verification logic.
pragma solidity ^0.8.20;

contract DepositVerifier {
    error PublicInputNotInField();
    error ProofInvalid();
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) public view {
        for (uint256 i = 0; i < 2; i++) {
            if (input[i] >= 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001) {
                revert PublicInputNotInField();
            }
        }
        if (proof[0] == 0) revert ProofInvalid();
    }
}
