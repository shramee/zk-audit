# Answer key — sol-gnark-abi fixture

Fixture: `testdata/sol-gnark-abi` (gnark v0.14.0 and Foundry). A redemption
circuit with two public inputs, the Solidity verifier gnark v0.14.0 exported
for it (`contracts/Verifier.sol`, with its verifying key in
`keys/verifier.vk`), and a caller that declares its own verifier interface.
Audits run on the sanitized copy made by
`evals/sanitize sol-gnark-abi <scratch>`.

| Id | Location | Real impact | Expected result |
|---|---|---|---|
| A1 | `contracts/Redeemer.sol` `IRedeemVerifier`, `redeem` | **Medium to high (completeness).** The interface declares `verifyProof(bytes,uint256[2]) returns (bool)`; gnark v0.14.0 exports `verifyProof(uint256[8],uint256[2])` with no return value (it reverts on an invalid proof). The selector is not in the verifier and the verifier has no fallback, so every redeem reverts, also with a valid proof; the verifier address is immutable, so the flow stays bricked until a redeploy. With a v0.15+ verifier the selector would match but the missing return value would still make the `bool` decode revert. `gnark-inventory verifier abi` reports both mismatches. PoC: `pocs/AbiMismatch.t.sol` (real verifier, real proof; honest control through the exported interface; sanity on the verifier itself). | confirmed, medium or high |
| A2 | `cmd/export/main.go` `groth16.Setup` | **High if these keys are deployed (trusted setup).** The export program runs a single-party setup and discards nothing it could keep: whoever ran it could keep the toxic waste and forge proofs. There is no ceremony artefact in the repository (`gnark-inventory verifier ceremony`). | needs_validation (trust: setup), high |

The circuit itself is sound for its statement; the fixture tests the
contract-to-verifier seam and setup provenance.
