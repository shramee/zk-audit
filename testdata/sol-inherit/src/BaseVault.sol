// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: the verification call lives in an abstract base,
// and the base declares the relayer modifier and the verifier state.
pragma solidity ^0.8.20;

import {IVerifier} from "./IVerifier.sol";

abstract contract BaseVault {
    IVerifier public verifier;
    address public relayer;
    mapping(uint256 => bool) public spentTags;

    modifier onlyRelayer() {
        require(msg.sender == relayer, "relayer");
        _;
    }

    function _checkAndSpend(uint256[8] calldata proof, uint256 tag, uint256 root) internal {
        require(!spentTags[tag], "spent");
        uint256[2] memory pub;
        pub[0] = tag;
        pub[1] = root;
        verifier.verifyProof(proof, pub);
        spentTags[tag] = true;
    }
}
