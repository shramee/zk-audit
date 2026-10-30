// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

contract Mixer {
    IVerifier public verifier;
    mapping(bytes32 => bool) public spent;

    constructor(address v) {
        verifier = IVerifier(v);
    }

    function deposit() external payable {}

    function withdraw(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        address payable recipient,
        uint256 value
    ) external {
        uint256[4] memory input = [root, nullifier, uint256(uint160(address(recipient))), value];
        require(verifier.verifyProof(proof, input), "bad proof");
        // BUG: replay protection keys on the proof bytes, which are malleable; a re-randomized proof for the same nullifier passes again.
        bytes32 tag = keccak256(proof);
        require(!spent[tag], "spent");
        spent[tag] = true;
        recipient.transfer(value);
    }
}
