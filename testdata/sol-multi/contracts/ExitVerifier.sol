// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: the public surface of a gnark PLONK verifier
// (template v0.9.1 or later), no verification logic.
pragma solidity ^0.8.20;

contract ExitVerifier {
    uint256 private constant VK_NB_PUBLIC_INPUTS = 3;

    function Verify(bytes calldata proof, uint256[] calldata public_inputs) public view returns (bool success) {
        require(public_inputs.length == VK_NB_PUBLIC_INPUTS);
        success = proof.length > 0;
    }
}
