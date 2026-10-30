// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

contract Mixer {
    IVerifier public verifier;
    mapping(uint256 => bool) public spent;
    mapping(uint256 => bool) public knownRoots;
    address public owner;

    constructor(address v) {
        verifier = IVerifier(v);
        owner = msg.sender;
    }

    function deposit() external payable {}

    function addRoot(uint256 root) external {
        require(msg.sender == owner, "owner");
        knownRoots[root] = true;
    }

    function withdraw(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        address payable recipient,
        uint256 value
    ) external {
        uint256[4] memory input = [root, nullifier, uint256(uint160(address(recipient))), value];
        require(verifier.verifyProof(proof, input), "bad proof");
        // BUG: the proof binds the root, but the contract never checks knownRoots[root], so a proof against an attacker-built tree is accepted.
        require(!spent[nullifier], "spent");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
