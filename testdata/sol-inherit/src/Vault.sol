// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: inherits a lib/ base through a remapping and a
// local abstract base; gates come from both.
pragma solidity ^0.8.20;

import {Ownable} from "@fakeoz/access/Ownable.sol";
import {BaseVault} from "./BaseVault.sol";
import {IVerifier} from "./IVerifier.sol";
import {Missing} from "@unknown/Missing.sol";

contract Vault is BaseVault, Ownable {
    uint256 public fee;

    constructor(address v) Ownable(msg.sender) {
        verifier = IVerifier(v);
    }

    function setVerifier(address v) external onlyOwner {
        verifier = IVerifier(v);
    }

    function setFee(uint256 f) external onlyRelayer {
        fee = f;
    }

    function redeem(uint256[8] calldata proof, uint256 tag, uint256 root, address payable to) external {
        _checkAndSpend(proof, tag, root);
        to.transfer(1 ether);
    }
}
