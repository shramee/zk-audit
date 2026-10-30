// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

import {IVerifier} from "./Verifier.sol";

// The circuit's public-witness order is [root, nullifier, recipient, value].
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
        // BUG: the input array swaps the nullifier and recipient slots, so the array the verifier checks does not match the circuit's public-witness order.
        uint256[4] memory input = [root, uint256(uint160(address(recipient))), nullifier, value];
        require(verifier.verifyProof(proof, input), "bad proof");
        require(!spent[nullifier], "spent");
        spent[nullifier] = true;
        recipient.transfer(value);
    }
}
