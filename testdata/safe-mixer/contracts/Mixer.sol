// SPDX-License-Identifier: UNLICENSED
// A mixer that consumes the withdrawal proof.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

// R is the BN254 scalar field order.
contract Mixer {
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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
        require(knownRoots[root], "unknown root");
        require(nullifier < R, "nullifier not in field");
        require(!spent[nullifier], "spent");
        // OK: input order matches the circuit's public-witness order
        // [root, nullifier, recipient, value]; recipient is bound.
        uint256[4] memory input = [root, nullifier, uint256(uint160(address(recipient))), value];
        require(verifier.verifyProof(proof, input), "bad proof");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
