// SPDX-License-Identifier: UNLICENSED
// Placeholder with the public surface of a generated gnark Groth16 verifier.
pragma solidity ^0.8.20;

interface IVerifier {
    function verifyProof(bytes calldata proof, uint256[4] calldata input) external view returns (bool);
}
