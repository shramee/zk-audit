package solidity

import (
	"regexp"
	"sort"
	"strings"
)

// EntryPoint is an external or public function that can change state
// (not view or pure) in a contract that is not a verifier, or its fallback
// or receive function. These are the contract-review units of the S1 lens:
// funds, external calls, signatures, initialisation and token handling
// beyond the verifier call.
type EntryPoint struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Contract   string   `json:"contract"`
	Function   string   `json:"function"`
	Visibility string   `json:"visibility"`
	Payable    bool     `json:"payable,omitempty"`
	Modifiers  []string `json:"modifiers,omitempty"`
	// Gate and Party are the sender restriction, as for Privileged.
	Gate  string `json:"gate"`
	Party string `json:"party"`
	// Effects summarise what the body does: eth-out, erc20, external-call,
	// low-level-call, delegatecall, signature, oracle, verify, state-write,
	// reentrancy-guard, initializer.
	Effects []string `json:"effects"`
}

var (
	reEthOut   = regexp.MustCompile(`\.\s*(send)\s*\(|\.call\s*\{\s*value\s*:|\bsendValue\s*\(`)
	reTransfer = regexp.MustCompile(`([A-Za-z_][\w.()\[\]]*)\s*\.\s*transfer\s*\(`)
	reERC20    = regexp.MustCompile(`\.\s*(transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove|safeIncreaseAllowance|forceApprove|permit)\s*\(`)
	reLowLvl   = regexp.MustCompile(`\.\s*(call|staticcall)\s*(\{[^}]*\})?\s*\(`)
	reDelegCl  = regexp.MustCompile(`\.\s*delegatecall\s*\(`)
	reSigUse   = regexp.MustCompile(`\becrecover\s*\(|\bECDSA\s*\.\s*(recover|tryRecover)\s*\(|\.\s*recover\s*\(|\bisValidSignature(Now)?\s*\(|\bSignatureChecker\b|\b_hashTypedDataV4\s*\(`)
	reOracle   = regexp.MustCompile(`\blatestRoundData\s*\(|\blatestAnswer\s*\(|\bgetPrice\w*\s*\(|\bconsult\s*\(|\bobserve\s*\(|\bgetReserves\s*\(|\bslot0\s*\(`)
	reGuard    = regexp.MustCompile(`\bnonReentrant\b|\bnoReentrancy\b|\block\b`)
	reMemberCl = regexp.MustCompile(`\b([A-Za-z_]\w*)(?:\s*\[[^\[\]]*\])*\s*\.\s*([A-Za-z_]\w*)\s*(?:\{[^}]*\})?\s*\(`)
)

// entryPoints records the external and public state-changing functions of
// a non-verifier contract.
func (s *scanner) entryPoints(u *unit, mods map[string]string) {
	if u.kind == "library" || u.kind == "interface" {
		return
	}
	body := u.src[u.blk.start:u.blk.end]
	for _, f := range u.fns {
		if f.start < 0 || strings.HasPrefix(f.name, "modifier ") || f.name == "constructor" {
			continue
		}
		vis, mut, fmods, _ := parseAfter(f.after)
		special := f.name == "fallback" || f.name == "receive"
		if !special && vis != "external" && vis != "public" {
			continue
		}
		if mut == "view" || mut == "pure" {
			continue
		}
		fbody := body[f.start:f.end]
		code := blankStrings(fbody)
		gate, party := gateOf(f.header, fbody, mods)
		if m := reInitMod.FindString(f.header); m != "" && party == "anyone" {
			gate, party = squash(m), "deployer"
		}
		eff := map[string]bool{}
		if reEthOut.MatchString(code) {
			eff["eth-out"] = true
		}
		for _, m := range reTransfer.FindAllStringSubmatchIndex(code, -1) {
			open := m[1] - 1
			if c := matchClose(code, open); c > 0 {
				if len(splitArgs(code[open+1:c])) == 1 {
					eff["eth-out"] = true
				} else {
					eff["erc20"] = true
				}
			}
		}
		if reERC20.MatchString(code) {
			eff["erc20"] = true
		}
		if reLowLvl.MatchString(code) {
			eff["low-level-call"] = true
		}
		if reDelegCl.MatchString(code) {
			eff["delegatecall"] = true
		}
		if reSigUse.MatchString(code) {
			eff["signature"] = true
		}
		if reOracle.MatchString(code) {
			eff["oracle"] = true
		}
		if reVerify.MatchString(code) {
			eff["verify"] = true
		}
		if reGuard.MatchString(f.header) {
			eff["reentrancy-guard"] = true
		}
		if reInitMod.MatchString(f.header) || strings.HasPrefix(f.name, "initialize") {
			eff["initializer"] = true
		}
		// calls on receivers typed as a contract or interface
		for _, m := range reMemberCl.FindAllStringSubmatch(code, -1) {
			recv := m[1]
			if recv == "abi" || recv == "super" || recv == "this" || recv == "msg" || recv == "block" || recv == "tx" || recv == "type" {
				continue
			}
			typ := s.varType(u, f, fbody, recv)
			if x, ok := s.byName[typ]; ok && x.kind != "library" {
				eff["external-call"] = true
				break
			}
		}
		for _, st := range splitStatements(code) {
			t := squash(st.text)
			if strings.HasPrefix(t, "delete ") {
				eff["state-write"] = true
				break
			}
			for name := range u.vars {
				if _, isConst := u.consts[name]; isConst {
					continue
				}
				if op := accessOp(t, name); op == "write" || op == "push" {
					eff["state-write"] = true
					break
				}
			}
		}
		var effects []string
		for e := range eff {
			effects = append(effects, e)
		}
		sort.Strings(effects)
		if effects == nil {
			effects = []string{}
		}
		if vis == "" {
			vis = "external"
		}
		s.res.EntryPoints = append(s.res.EntryPoints, EntryPoint{File: u.file, Line: u.li.line(u.blk.start + f.headerOff),
			Contract: u.name, Function: f.name, Visibility: vis, Payable: mut == "payable", Modifiers: fmods,
			Gate: gate, Party: party, Effects: effects})
	}
}
