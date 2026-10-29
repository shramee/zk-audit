// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

// R is the BN254 scalar field order; public inputs are taken modulo R by any
// correct pairing-based verifier.
contract Mixer {
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IVerifier public verifier;
    mapping(uint256 => bool) public spent;

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
        // BUG: the nullifier is not required to be < R before it keys the spent map; the verifier reduces it mod R, so nullifier and nullifier+R alias to one note but are two distinct keys.
        require(!spent[nullifier], "spent");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
