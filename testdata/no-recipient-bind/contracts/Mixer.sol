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
        // BUG: recipient is not part of the proof statement (only root, nullifier, value are), so a front-runner resubmits the same proof with their own recipient.
        uint256[3] memory input = [root, nullifier, value];
        require(verifier.verifyProof(proof, input), "bad proof");
        require(!spent[nullifier], "spent");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
