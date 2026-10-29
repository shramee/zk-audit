// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: verification through a library, a `using` directive and an
// inherited verifier contract.
pragma solidity ^0.8.20;

import {Groth16Lib} from "./Groth16Lib.sol";
import {HandVerifier} from "./HandVerifier.sol";

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return proof.length == 0 && root == leaf;
    }
}

contract Claims is HandVerifier {
    using Groth16Lib for Groth16Lib.Proof;
    mapping(uint256 => bool) public claimed;

    function claim(Groth16Lib.Proof memory proof, uint256 id) external {
        require(proof.verify([id]), "bad proof");
        claimed[id] = true;
    }

    function claimDirect(Groth16Lib.Proof memory proof, uint256 id) external {
        require(Groth16Lib.verify(proof, [id]), "bad proof");
        claimed[id] = true;
    }

    function claimInherited(uint256[8] memory proof, uint256 id) external {
        require(verifyProof(proof, [id]), "bad proof");
        claimed[id] = true;
    }

    function claimListed(bytes32[] memory path, bytes32 root, bytes32 leaf) external {
        require(MerkleProof.verify(path, root, leaf), "not listed");
    }
}
