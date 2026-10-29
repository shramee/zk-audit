// SPDX-License-Identifier: UNLICENSED
// zk-audit test fixture with a deliberate liveness bug.
pragma solidity ^0.8.20;

interface IRingVerifier {
    function verifyProof(bytes calldata proof, uint256[3] calldata input) external view returns (bool);
}

/// @notice Fixed-denomination shielded pool. Withdrawals prove membership
/// against one of the recent Merkle roots kept in a ring buffer.
contract RootRing {
    // BUG: a window of 8 roots; any depositor evicts a pending proof's root.
    uint32 public constant ROOT_HISTORY = 8;

    IRingVerifier public immutable verifier;
    uint256 public immutable denomination;

    uint256[ROOT_HISTORY] public roots;
    uint32 public currentRootIndex;
    uint256 public nextIndex;
    mapping(uint256 => bool) public spent;

    event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 root);
    event Withdrawal(address to, uint256 nullifier);

    constructor(IRingVerifier v, uint256 d) {
        verifier = v;
        denomination = d;
        roots[0] = uint256(keccak256("empty tree"));
    }

    /// Inserts a commitment. The keccak chain stands in for the incremental
    /// tree update; each insert produces a new root.
    function deposit(uint256 commitment) external payable {
        require(msg.value == denomination, "denomination");
        uint256 root = uint256(keccak256(abi.encode(roots[currentRootIndex], commitment, nextIndex)));
        emit Deposit(commitment, nextIndex, root);
        nextIndex++;
        currentRootIndex = (currentRootIndex + 1) % ROOT_HISTORY;
        roots[currentRootIndex] = root;
    }

    function latestRoot() external view returns (uint256) {
        return roots[currentRootIndex];
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint32 i = 0; i < ROOT_HISTORY; i++) {
            if (roots[i] == root) return true;
        }
        return false;
    }

    function withdraw(bytes calldata proof, uint256 root, uint256 nullifier, address payable to) external {
        require(isKnownRoot(root), "unknown root");
        require(!spent[nullifier], "spent");
        require(verifier.verifyProof(proof, [root, nullifier, uint256(uint160(address(to)))]), "invalid proof");
        spent[nullifier] = true;
        emit Withdrawal(to, nullifier);
        to.transfer(denomination);
    }
}
