// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: interface in its own file.
pragma solidity ^0.8.20;

interface IVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) external view;
}
