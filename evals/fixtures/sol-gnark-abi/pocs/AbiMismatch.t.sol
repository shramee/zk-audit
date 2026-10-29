// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Eval PoC for the sol-gnark-abi fixture (T-FOUNDRY-VERIFIER against the
// real verifier gnark v0.14.0 exported, with a real proof). No forge-std.
// Run by evals/run-pocs.
import {Verifier} from "../contracts/Verifier.sol";
import {Redeemer, IRedeemVerifier} from "../contracts/Redeemer.sol";

// The interface gnark v0.14.0 exports: uint256[8] proof, no return value,
// reverts on an invalid proof.
interface IGnarkVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) external view;
}

// The control: the same redemption written against the exported interface.
contract FixedRedeemer {
    IGnarkVerifier public immutable verifier;
    mapping(uint256 => bool) public redeemed;

    constructor(IGnarkVerifier v) {
        verifier = v;
    }

    function redeem(uint256[8] calldata proof, uint256 tag, uint256 root) external {
        require(!redeemed[tag], "redeemed");
        verifier.verifyProof(proof, [tag, root]);
        redeemed[tag] = true;
    }
}

contract PoC_VerifierAbiMismatch {
    Verifier verifier;
    Redeemer redeemer;
    FixedRedeemer fixedRedeemer;

    // A proof for Tag = 14, Root = 5 (Secret = 3), made with the proving key
    // of the committed verifier (gnark v0.14.0, groth16.Prove, MarshalSolidity).
    uint256 constant TAG = 14;
    uint256 constant ROOT = 5;

    function proof() internal pure returns (uint256[8] memory p) {
        p[0] = 0x291191e8fa8edc92e870284bd54b41d066137709eb647e88e8ccea0042144dc5;
        p[1] = 0x227a5a87a714b21d59dfabb115d1db839ecf278d5a86f27a52858295bbda41e9;
        p[2] = 0x453ab13f8aeaf8fbb99363fb2e8f27c92de195ea36501377a24a8997adfd4f;
        p[3] = 0x201e17f48f3ca84e150f3e2fe6c5032ce75dfd6a1690a93d93da11b8dbbaa94;
        p[4] = 0x2079287c7984ff5a932e934322ac48ac9aaab548d75c284900a9085bd7ce462c;
        p[5] = 0x23e6b587c5b29805d925173ece052c0bf76ad6631aa48adf4a276a7ee2d78694;
        p[6] = 0x2f5d22822747633f8f78fdcdfee01ad93fcde7b8716f8fb3622ad8a0cebe50d2;
        p[7] = 0x1dd742bc60706c8c796974fad1f3de828aa777bbe308b16f9b8961b00db1c706;
    }

    function setUp() public {
        verifier = new Verifier();
        redeemer = new Redeemer(IRedeemVerifier(address(verifier)));
        fixedRedeemer = new FixedRedeemer(IGnarkVerifier(address(verifier)));
    }

    // Sanity: the proof is valid for (TAG, ROOT) on the real verifier, and a
    // wrong public input is rejected, so the verifier under test is live.
    function test_sanity_proofVerifiesOnTheExportedVerifier() public view {
        verifier.verifyProof(proof(), [TAG, ROOT]);
        try verifier.verifyProof(proof(), [TAG + 1, ROOT]) {
            revert("a wrong public input verified");
        } catch {}
    }

    // Attack (completeness): the honest holder of a valid proof cannot
    // redeem. The interface's selector is not in the verifier, which has no
    // fallback, so the call reverts with empty data before any check runs.
    function test_attack_validProofCannotRedeem() public {
        uint256[8] memory p = proof();
        bytes memory packed = abi.encodePacked(p);
        try redeemer.redeem(packed, TAG, ROOT) {
            revert("redeem accepted a call the verifier cannot answer");
        } catch (bytes memory reason) {
            require(reason.length == 0, "expected a revert without data (unknown selector)");
        }
        require(!redeemer.redeemed(TAG), "tag marked redeemed");
        bytes4 asked = IRedeemVerifier.verifyProof.selector;
        bytes4 exported = IGnarkVerifier.verifyProof.selector;
        require(asked != exported, "selectors should differ");
    }

    // Honest control: the same proof redeems through the exported interface.
    function test_control_exportedInterfaceRedeems() public {
        fixedRedeemer.redeem(proof(), TAG, ROOT);
        require(fixedRedeemer.redeemed(TAG), "control did not redeem");
    }
}
