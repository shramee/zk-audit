// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with deliberate integration bugs.
pragma solidity ^0.8.20;

interface IVerifier {
    function verifyProof(bytes calldata proof, uint256[7] calldata input) external view;
}

contract Pool {
    IVerifier public verifier;
    mapping(uint256 => bool) public nullifiers;
    mapping(uint256 => bool) public knownRoots;
    address public owner;

    constructor(address v) {
        owner = msg.sender;
        verifier = IVerifier(v);
    }

    function setVerifier(address v) external {
        require(msg.sender == owner, "owner");
        verifier = IVerifier(v);
    }

    function addRoot(uint256 root) external {
        require(msg.sender == owner, "owner");
        knownRoots[root] = true;
    }

    function withdraw(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        address recipient,
        uint256 fee0,
        uint256 fee1,
        uint256 value,
        uint256 ownerKey
    ) external {
        require(knownRoots[root], "unknown root");
        require(!nullifiers[nullifier], "spent");
        uint256[7] memory input;
        input[0] = root;
        input[1] = nullifier;
        input[2] = uint256(uint160(recipient));
        input[3] = fee0;
        input[4] = fee1;
        input[5] = value;
        input[6] = ownerKey;
        verifier.verifyProof(proof, input);
        nullifiers[nullifier] = true;
        payable(recipient).transfer(value);
    }
}
