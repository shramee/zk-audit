package solidity

import (
	"regexp"
	"strconv"
	"strings"
)

// Verifier generators. A verifier whose generator is not gnark is routed to
// the custom-verifier vector slice (hand-written or other-toolchain
// verifiers need their transcript, precompile and input checks read by hand).
const (
	GenGnark        = "gnark"
	GenSnarkjs      = "snarkjs"
	GenZokrates     = "zokrates"
	GenBarretenberg = "barretenberg"
	GenHalo2        = "halo2"
	GenSP1          = "sp1"
	GenRisc0        = "risc0"
	GenHandWritten  = "hand-written"
)

var (
	reGrothSig     = regexp.MustCompile(`function\s+verifyProof\s*\(([^)]*)\)`)
	reFixed        = regexp.MustCompile(`uint(?:256)?\s*\[\s*(\d+)\s*\]\s*(?:calldata|memory)\s+\w+\s*$`)
	rePlonkN       = regexp.MustCompile(`VK_NB_PUBLIC_INPUTS\s*=\s*(\d+)`)
	reSnarkjsN     = regexp.MustCompile(`uint(?:256)?\s*\[\s*(\d+)\s*\]\s*calldata\s+_?pubSignals`)
	rePrecompile   = regexp.MustCompile(`staticcall\s*\(\s*(?:gas\s*\(\s*\)|[A-Za-z_]\w*|sub\s*\([^)]*\)|not\s*\(\s*0\s*\)|\d+)\s*,\s*(0x0*[678]|[678]|PRECOMPILE_\w+|ECPAIRING|ECADD|ECMUL|BN254_\w+)\s*,`)
	rePrecompileHL = regexp.MustCompile(`address\s*\(\s*(0x0*[678]|[678])\s*\)\s*\.\s*staticcall`)
	reVerifyFnName = regexp.MustCompile(`function\s+(verifyProof|verify|Verify|verifyTx|verify_serialized_proof|verifyCompressedProof)\s*\(`)
	reAnyN         = regexp.MustCompile(`uint(?:256)?\s*\[\s*(\d+)\s*\]\s*(?:calldata|memory)\s+_?(?:input|inputs|pubSignals|publicInputs|public_inputs|instances|pubs)\b`)
)

// classifyVerifier decides whether a contract or library body is a SNARK
// verifier and which generator and template produced it. raw is the body
// with comments (templates mark themselves in comments), file the whole
// file with comments, body the comment-stripped body.
func classifyVerifier(name, body, raw, file string) (Verifier, bool) {
	v := Verifier{NbPublic: -1}
	has := func(s string) bool { return strings.Contains(body, s) }
	pairing := rePrecompile.MatchString(body) || rePrecompileHL.MatchString(body) || strings.Contains(strings.ToLower(body), "pairing")
	switch {
	case has("PublicInputNotInField") && has("function verifyProof"):
		v.Kind, v.Generator = "gnark-groth16", GenGnark
		v.Commitments = has("CommitmentInvalid")
		if m := reGrothSig.FindStringSubmatch(body); m != nil {
			args := splitArgs(m[1])
			if len(args) > 0 {
				if n := reFixed.FindStringSubmatch(args[len(args)-1]); n != nil {
					v.NbPublic, _ = strconv.Atoi(n[1])
				}
			}
			switch {
			case len(args) > 0 && strings.HasPrefix(squash(args[0]), "bytes "):
				v.Template = "gnark Groth16 template v0.15.0 or later: verifyProof(bytes proof, uint256[N] input), reverts on failure"
			case len(args) > 0 && strings.HasPrefix(squash(args[0]), "uint256[8]"):
				v.Template = "gnark Groth16 template v0.9.0 to v0.14.x: verifyProof(uint256[8] proof, ..., uint256[N] input), reverts on failure"
			}
		}
	case has("VK_NB_PUBLIC_INPUTS") && has("function Verify"):
		v.Kind, v.Generator = "gnark-plonk", GenGnark
		v.Template = "gnark PLONK template v0.9.1 or later: Verify(bytes proof, uint256[] public_inputs) returns (bool)"
		if m := rePlonkN.FindStringSubmatch(body); m != nil {
			v.NbPublic, _ = strconv.Atoi(m[1])
		}
	case has("vk_domain_size") && has("function Verify"):
		v.Kind, v.Generator = "gnark-plonk", GenGnark
		v.Template = "gnark PLONK template v0.9.0 (lower-case constants): affected by GHSA-7p92-x423-vwj6"
	case has("function verify_serialized_proof") && has("vk.num_inputs"):
		v.Kind, v.Generator = "gnark-plonk", GenGnark
		v.Template = "gnark PLONK template before v0.9.0 (verify_serialized_proof): affected by GHSA-7p92-x423-vwj6"
	case strings.Contains(raw, "K in gnark") && has("function verifyProof"):
		v.Kind, v.Generator = "gnark-groth16", GenGnark
		v.Template = "gnark Groth16 template before v0.9.0: verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[N] input) returns (bool r)"
		v.NbPublic = lastFixedLen(body, "verifyProof")
	case has("function verifyProof") && has("checkField") && has("_pubSignals"):
		v.Generator = GenSnarkjs
		switch {
		case has("_pA") || has("checkPairing"):
			v.Kind = "snarkjs-groth16"
		case strings.Contains(name, "Fflonk") || has("fflonk"):
			v.Kind = "snarkjs-fflonk"
		default:
			v.Kind = "snarkjs-plonk"
		}
		if m := reSnarkjsN.FindStringSubmatch(body); m != nil {
			v.NbPublic, _ = strconv.Atoi(m[1])
		}
	case has("function verifyTx") && pairing:
		v.Kind, v.Generator = "zokrates-groth16", GenZokrates
		v.NbPublic = lastFixedLen(body, "verifyTx")
	case strings.Contains(name, "UltraVerifier") || strings.Contains(name, "HonkVerifier") || has("BaseUltraVerifier") ||
		(has("bytes32[] calldata _publicInputs") && has("function verify")):
		v.Kind, v.Generator = "noir-barretenberg", GenBarretenberg
	case strings.Contains(name, "Halo2Verifier") || (has("uint256[] calldata instances") && has("function verifyProof")):
		v.Kind, v.Generator = "halo2", GenHalo2
	case strings.Contains(name, "SP1Verifier") || has("VERIFIER_HASH") && has("programVKey"):
		v.Kind, v.Generator = "sp1", GenSP1
	case strings.Contains(name, "RiscZero") && (has("function verify") || has("imageId")):
		v.Kind, v.Generator = "risc0", GenRisc0
	case reVerifyFnName.MatchString(body) && pairing:
		v.Kind, v.Generator = "custom", GenHandWritten
		v.NbPublic = anyFixedLen(body)
	default:
		return v, false
	}
	if v.Generator == GenGnark && strings.Contains(file, "Code generated by gnark DO NOT EDIT") {
		v.Marker = "Code generated by gnark DO NOT EDIT"
	}
	v.Precompiles = precompilesOf(body)
	return v, true
}

func lastFixedLen(body, fn string) int {
	re := regexp.MustCompile(`function\s+` + fn + `\s*\(([^)]*)\)`)
	if m := re.FindStringSubmatch(body); m != nil {
		args := splitArgs(m[1])
		if len(args) > 0 {
			if n := reFixed.FindStringSubmatch(args[len(args)-1]); n != nil {
				x, _ := strconv.Atoi(n[1])
				return x
			}
		}
	}
	return -1
}

func anyFixedLen(body string) int {
	if m := reAnyN.FindStringSubmatch(body); m != nil {
		x, _ := strconv.Atoi(m[1])
		return x
	}
	return -1
}

// precompilesOf lists the BN254 precompiles a verifier calls (ecAdd 0x06,
// ecMul 0x07, ecPairing 0x08, modexp 0x05) as named constants or literals.
func precompilesOf(body string) []string {
	var out []string
	for _, p := range []struct {
		name string
		re   *regexp.Regexp
	}{
		{"modexp", regexp.MustCompile(`(?i)\b(0x0*5|PRECOMPILE_MODEXP|MODEXP)\b`)},
		{"ecAdd", regexp.MustCompile(`(?i)\b(0x0*6|PRECOMPILE_ADD|ECADD|EC_ADD)\b`)},
		{"ecMul", regexp.MustCompile(`(?i)\b(0x0*7|PRECOMPILE_MUL|ECMUL|EC_MUL)\b`)},
		{"ecPairing", regexp.MustCompile(`(?i)\b(0x0*8|PRECOMPILE_VERIFY|ECPAIRING|EC_PAIRING|PAIRING_PRECOMPILE)\b`)},
	} {
		if p.re.MatchString(body) {
			out = append(out, p.name)
		}
	}
	return out
}
