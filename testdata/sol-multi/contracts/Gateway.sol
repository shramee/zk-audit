// SPDX-License-Identifier: UNLICENSED
// zk-audit scanner fixture: two verifiers behind two interfaces, an
// overloaded verifyProof, a low-level staticcall and a registry of verifiers.
pragma solidity ^0.8.20;

interface IDepositVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) external view;
    function verifyProof(bytes calldata proof, uint256[2] calldata input) external view;
}

interface IExitVerifier {
    function Verify(bytes calldata proof, uint256[] calldata pubs) external view returns (bool);
}

contract Gateway {
    IDepositVerifier public depositVerifier;
    IExitVerifier public exitVerifier;
    mapping(uint256 => IExitVerifier) public exitVerifiers;
    mapping(uint256 => bool) public usedNotes;

    constructor(address d, address e) {
        depositVerifier = IDepositVerifier(d);
        exitVerifier = IExitVerifier(e);
    }

    function deposit(uint256[8] calldata proof, uint256 note, uint256 amount) external {
        depositVerifier.verifyProof(proof, [note, amount]);
        usedNotes[note] = true;
    }

    function exit(bytes calldata proof, uint256 note, uint256 root, uint256 to) external {
        uint256[] memory pubs = new uint256[](3);
        pubs[0] = note;
        pubs[1] = root;
        pubs[2] = to;
        require(exitVerifier.Verify(proof, pubs), "bad proof");
    }

    function exitVia(uint256 id, bytes calldata proof, uint256[] calldata pubs) external {
        exitVerifiers[id].Verify(proof, pubs);
    }

    function depositRaw(uint256[8] calldata proof, uint256 note, uint256 amount) external {
        uint256[2] memory input = [note, amount];
        (bool ok, ) = address(depositVerifier).staticcall(
            abi.encodeWithSelector(IDepositVerifier.verifyProof.selector, proof, input)
        );
        usedNotes[note] = true;
        ok;
    }

    function depositSig(bytes calldata proof, uint256 note, uint256 amount) external {
        (bool ok, bytes memory ret) = address(depositVerifier).staticcall(
            abi.encodeWithSignature("verifyProof(bytes,uint256[2])", proof, [note, amount])
        );
        require(ok && abi.decode(ret, (bool)), "bad proof");
        usedNotes[note] = true;
    }

    function exitCall(bytes calldata proof, uint256[] calldata pubs) external {
        (bool ok, ) = address(exitVerifier).staticcall(abi.encodeCall(IExitVerifier.Verify, (proof, pubs)));
        if (!ok) revert();
    }
}
