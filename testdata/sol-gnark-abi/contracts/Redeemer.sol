// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate integration bug.
pragma solidity ^0.8.20;

// BUG: this interface does not match the verifier gnark v0.14.0 exports
// (verifyProof(uint256[8],uint256[2]), no return value): the selector differs
// and the bool return is never sent, so every redeem reverts.
interface IRedeemVerifier {
    function verifyProof(bytes calldata proof, uint256[2] calldata input) external view returns (bool);
}

contract Redeemer {
    IRedeemVerifier public immutable verifier;
    mapping(uint256 => bool) public redeemed;

    event Redeemed(uint256 indexed tag, address indexed to);

    constructor(IRedeemVerifier v) {
        verifier = v;
    }

    function redeem(bytes calldata proof, uint256 tag, uint256 root) external {
        require(!redeemed[tag], "redeemed");
        require(verifier.verifyProof(proof, [tag, root]), "bad proof");
        redeemed[tag] = true;
        emit Redeemed(tag, msg.sender);
    }
}
