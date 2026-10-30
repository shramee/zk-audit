// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

// Two deployments of this mixer can share one verifier and root set. The proof
// statement is [root, nullifier, recipient, value].
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
        require(knownRoots[root], "unknown root");
        require(!spent[nullifier], "spent");
        // BUG: the statement has no chain id or contract address, so a proof made for one deployment is accepted by any other deployment that shares the verifier and the root.
        uint256[4] memory input = [root, nullifier, uint256(uint160(address(recipient))), value];
        require(verifier.verifyProof(proof, input), "bad proof");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
