// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

contract Mixer {
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
        // BUG: the nullifier is never recorded in `spent`, so the same proof and nullifier withdraw repeatedly.
        recipient.transfer(value);
    }
}
