package solidity

import (
	"regexp"
	"sort"
	"strings"
)

// Privileged is an external or public function that only a privileged party
// can call (an access modifier or a sender check), or that writes
// trust-critical state (verifier, verifying key, authority, implementation)
// with no sender check. These are the trusted-party surfaces the T1 lens
// owns: what the owner, an admin role, an upgrader or a relayer can change.
type Privileged struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Function string `json:"function"`
	// Gate is the sender restriction as written (`onlyOwner`,
	// `require(msg.sender == owner)`), or "none" when no check was found.
	Gate string `json:"gate"`
	// Party is who passes the gate: owner, role:<NAME>, a variable or
	// modifier-derived name, or "anyone" when Gate is "none".
	Party string `json:"party"`
	// Powers summarises what the function changes: verifier, vk, root,
	// nullifier, authority, upgrade, funds, pause, config.
	Powers []string `json:"powers"`
	// Writes lists the contract-level variables the function assigns.
	Writes []string `json:"writes,omitempty"`
}

// Role is a privileged party a contract declares: an owner, an access
// control role, or an address variable named for a role (admin, relayer,
// sequencer, operator, ...).
type Role struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Name     string `json:"name"`
	// Kind: owner, role, admin, operator, relayer, sequencer, prover,
	// oracle, guardian, upgrader, signer.
	Kind string `json:"kind"`
	// Source: inherits <Base>, state variable, role constant, modifier.
	Source string `json:"source"`
}

// Upgrade is a path that replaces or runs other code in the contract's
// context: a proxy base, an upgrade call, delegatecall, selfdestruct, an
// `_authorizeUpgrade` hook or an initializer.
type Upgrade struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Function string `json:"function,omitempty"`
	// Kind: proxy-base, upgrade-call, authorize-upgrade, delegatecall,
	// selfdestruct, initializer.
	Kind string `json:"kind"`
	Text string `json:"text"`
}

var (
	reOnlyRole   = regexp.MustCompile(`\bonlyRole\s*\(\s*([A-Za-z_][\w.]*)\s*\)`)
	reOnlyX      = regexp.MustCompile(`\b(only[A-Z]\w*)\b`)
	reAuthMod    = regexp.MustCompile(`\b(requiresAuth|auth)\b`)
	reInitMod    = regexp.MustCompile(`\b(initializer|reinitializer\s*\([^)]*\))`)
	reSenderEq   = regexp.MustCompile(`(?:msg\.sender|_msgSender\(\))\s*(?:==|!=)\s*([A-Za-z_][\w.]*(?:\s*\(\s*\))?)`)
	reEqSender   = regexp.MustCompile(`([A-Za-z_][\w.]*(?:\s*\(\s*\))?)\s*(?:==|!=)\s*(?:msg\.sender|_msgSender\(\))`)
	reCheckOwner = regexp.MustCompile(`\b_?checkOwner\s*\(\s*\)|\b_onlyOwner\s*\(\s*\)`)
	reCheckRole  = regexp.MustCompile(`\b_checkRole\s*\(\s*([A-Za-z_][\w.]*)`)
	reHasRole    = regexp.MustCompile(`\bhasRole\s*\(\s*([A-Za-z_][\w.]*)\s*,\s*(?:msg\.sender|_msgSender\(\))`)
	reRoleConst  = regexp.MustCompile(`\bbytes32\b[^;=]*\bconstant\s+([A-Z][A-Z0-9_]*_ROLE)\b`)
	reAuthority  = regexp.MustCompile(`(?i)(owner|admin|governor|governance|operator|relayer|sequencer|guardian|keeper|prover|signer|oracle|pauser|upgrader|updater|committee)`)
	reInherits   = regexp.MustCompile(`\bis\s+([^{]+)$`)
	reUpgradeFn  = regexp.MustCompile(`\b(_?upgradeTo(?:AndCall)?|_upgradeToAndCallUUPS|_setImplementation)\s*\(`)
	reDelegate   = regexp.MustCompile(`\.\s*delegatecall\s*\(|\bdelegatecall\s*\(`)
	reSelfDest   = regexp.MustCompile(`\bselfdestruct\s*\(`)
	reFunds      = regexp.MustCompile(`\.\s*(transfer|send)\s*\(|\.call\s*\{\s*value|\b(safeTransfer|safeTransferFrom|_mint|mint|_transfer)\s*\(`)
	reAuthCall   = regexp.MustCompile(`\b(_?grantRole|_?revokeRole|_setRoleAdmin|_?transferOwnership|renounceOwnership)\s*\(`)
	rePauseCall  = regexp.MustCompile(`\b_(un)?pause\s*\(\s*\)`)
)

// proxyBases are base contracts that make a contract upgradeable or a proxy.
var proxyBases = map[string]bool{
	"UUPSUpgradeable": true, "Initializable": true, "ERC1967Upgrade": true, "ERC1967UpgradeUpgradeable": true,
	"ERC1967Proxy": true, "TransparentUpgradeableProxy": true, "BeaconProxy": true, "Proxy": true, "UpgradeableBeacon": true,
}

// ownerBases are base contracts that give the contract an owner.
var ownerBases = map[string]bool{
	"Ownable": true, "Ownable2Step": true, "OwnableUpgradeable": true, "Ownable2StepUpgradeable": true, "Owned": true,
}

// roleBases are base contracts that give the contract access-control roles.
var roleBases = map[string]bool{
	"AccessControl": true, "AccessControlEnumerable": true, "AccessControlUpgradeable": true,
	"AccessControlEnumerableUpgradeable": true, "AccessControlDefaultAdminRules": true,
}

// sigFn is one function (or modifier) of a contract with its header.
type sigFn struct {
	name       string
	header     string // from `function` to the opening brace
	headerOff  int    // offset of the header in the contract body
	start, end int    // body offsets inside the contract body
}

// inheritance returns the base contract names of a contract header.
func inheritance(header string) []string {
	m := reInherits.FindStringSubmatch(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(header), "{")))
	if m == nil {
		return nil
	}
	var out []string
	for _, b := range splitArgs(m[1]) {
		b = strings.TrimSpace(b)
		if i := strings.IndexByte(b, '('); i >= 0 {
			b = b[:i]
		}
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	return out
}

// roleKind maps a party name to a role kind.
func roleKind(name string) string {
	n := strings.ToLower(name)
	for _, k := range []struct{ needle, kind string }{
		{"upgrader", "upgrader"}, {"owner", "owner"}, {"admin", "admin"}, {"governor", "admin"}, {"governance", "admin"},
		{"relayer", "relayer"}, {"sequencer", "sequencer"}, {"operator", "operator"}, {"prover", "prover"},
		{"oracle", "oracle"}, {"guardian", "guardian"}, {"pauser", "guardian"}, {"keeper", "operator"},
		{"updater", "operator"}, {"committee", "operator"}, {"signer", "signer"},
	} {
		if strings.Contains(n, k.needle) {
			return k.kind
		}
	}
	if strings.HasSuffix(name, "_ROLE") {
		return "role"
	}
	return "admin"
}

// varKind classifies a contract-level variable for the Powers summary.
func varKind(name, decl string) string {
	if k := stateKind(name, decl); k != "" {
		return k
	}
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "implementation"):
		return "implementation"
	case strings.Contains(n, "paused"):
		return "paused"
	case reAuthority.MatchString(name) && (strings.Contains(decl, "address") || strings.Contains(decl, "mapping")):
		return "authority"
	}
	return "config"
}

// power maps a variable kind to a Powers entry.
func power(kind string) string {
	switch kind {
	case "verifier", "vk", "root", "nullifier", "commitment", "authority", "nonce":
		return kind
	case "implementation":
		return "upgrade"
	case "paused":
		return "pause"
	}
	return "config"
}

// gateOf returns the sender restriction of a function and the party that
// passes it, from its modifiers and its body. mods maps a modifier defined in
// the contract to the party its own sender check names.
func gateOf(header, body string, mods map[string]string) (gate, party string) {
	if m := reOnlyRole.FindStringSubmatch(header); m != nil {
		return squash(m[0]), "role:" + m[1]
	}
	for _, m := range reOnlyX.FindAllStringSubmatch(header, -1) {
		if p, ok := mods[m[1]]; ok && p != "" {
			return m[1], p
		}
		if m[1] == "onlyOwner" {
			return m[1], "owner"
		}
		if m[1] == "onlyProxy" || m[1] == "onlyDelegateCall" {
			continue
		}
		return m[1], strings.ToLower(m[1][4:5]) + m[1][5:]
	}
	var names []string
	for name := range mods {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if p := mods[name]; p != "" && regexp.MustCompile(`\b`+regexp.QuoteMeta(name)+`\b`).MatchString(header) {
			return name, p
		}
	}
	if m := reAuthMod.FindStringSubmatch(header); m != nil {
		return m[1], "authority"
	}
	if reCheckOwner.MatchString(body) {
		return squash(reCheckOwner.FindString(body)), "owner"
	}
	if m := reCheckRole.FindStringSubmatch(body); m != nil {
		return squash(m[0]) + ")", "role:" + m[1]
	}
	if m := reHasRole.FindStringSubmatch(body); m != nil {
		return squash(m[0]) + ")", "role:" + m[1]
	}
	for _, st := range splitStatements(body) {
		t := squash(st.text)
		if !(strings.HasPrefix(t, "require") || strings.HasPrefix(t, "if") || strings.HasPrefix(t, "assert")) {
			continue
		}
		for _, re := range []*regexp.Regexp{reSenderEq, reEqSender} {
			if m := re.FindStringSubmatch(t); m != nil {
				p := strings.TrimSpace(strings.TrimSuffix(strings.ReplaceAll(m[1], " ", ""), "()"))
				if p == "msg.sender" || p == "tx.origin" || p == "" {
					continue
				}
				g := t
				if len(g) > 80 {
					g = g[:77] + "..."
				}
				return g, p
			}
		}
	}
	return "none", "anyone"
}

// modifierParty returns the party a modifier body checks, or "".
func modifierParty(body string) string {
	if _, p := gateOf("", body, nil); p != "anyone" {
		return p
	}
	return ""
}

// scanPrivileged records privileged functions, roles and upgrade paths of
// one contract. level is the contract body with function bodies blanked.
func scanPrivileged(res *Result, rel, src string, li lineIndex, c block, contractHeader string, fns []sigFn, level string) {
	body := src[c.start:c.end]
	roles := map[string]bool{}
	addRole := func(line int, name, kind, source string) {
		if name == "" || roles[name] {
			return
		}
		roles[name] = true
		res.Roles = append(res.Roles, Role{File: rel, Line: line, Contract: c.name, Name: name, Kind: kind, Source: source})
	}
	for _, base := range inheritance(contractHeader) {
		switch {
		case ownerBases[base]:
			addRole(c.headerLine, "owner", "owner", "inherits "+base)
		case roleBases[base]:
			addRole(c.headerLine, "DEFAULT_ADMIN_ROLE", "role", "inherits "+base)
		case proxyBases[base]:
			res.Upgrades = append(res.Upgrades, Upgrade{File: rel, Line: c.headerLine, Contract: c.name, Kind: "proxy-base", Text: "inherits " + base})
		}
	}
	// contract-level variables: every non-constant, non-immutable declaration
	vars := map[string]string{}
	var varNames []string
	for _, st := range splitStatements(level) {
		text := squash(st.text)
		if text == "" {
			continue
		}
		switch strings.Fields(text)[0] {
		case "event", "error", "struct", "enum", "using", "pragma", "import", "}", "{", "modifier", "function":
			continue
		}
		line := li.line(c.start + st.off)
		if m := reRoleConst.FindStringSubmatch(text); m != nil {
			addRole(line, m[1], "role", "role constant")
			continue
		}
		if strings.Contains(" "+text+" ", " constant ") || strings.Contains(" "+text+" ", " immutable ") {
			continue
		}
		name := stateVarName(text)
		if name == "" || !reIdent.MatchString(name) {
			continue
		}
		kind := varKind(name, text)
		vars[name] = kind
		varNames = append(varNames, name)
		if kind == "authority" {
			addRole(line, name, roleKind(name), "state variable")
		}
	}
	sort.Strings(varNames)
	// modifiers defined in this contract and the party each checks
	mods := map[string]string{}
	for _, f := range fns {
		if strings.HasPrefix(f.name, "modifier ") {
			mods[strings.TrimPrefix(f.name, "modifier ")] = modifierParty(body[f.start:f.end])
		}
	}
	for _, f := range fns {
		fbody := body[f.start:f.end]
		line := li.line(c.start + f.headerOff)
		if strings.HasPrefix(f.name, "modifier ") {
			if p := mods[strings.TrimPrefix(f.name, "modifier ")]; p != "" {
				addRole(line, strings.TrimPrefix(p, "role:"), roleKind(p), "modifier "+strings.TrimPrefix(f.name, "modifier "))
			}
			continue
		}
		// upgrade paths in any function
		if f.name == "_authorizeUpgrade" {
			res.Upgrades = append(res.Upgrades, Upgrade{File: rel, Line: line, Contract: c.name, Function: f.name, Kind: "authorize-upgrade", Text: squash(f.header)})
		}
		if m := reInitMod.FindString(f.header); m != "" {
			res.Upgrades = append(res.Upgrades, Upgrade{File: rel, Line: line, Contract: c.name, Function: f.name, Kind: "initializer", Text: squash(m)})
		}
		for _, k := range []struct {
			re   *regexp.Regexp
			kind string
		}{{reUpgradeFn, "upgrade-call"}, {reDelegate, "delegatecall"}, {reSelfDest, "selfdestruct"}} {
			for _, m := range k.re.FindAllStringIndex(fbody, -1) {
				res.Upgrades = append(res.Upgrades, Upgrade{File: rel, Line: li.line(c.start + f.start + m[0]), Contract: c.name, Function: f.name,
					Kind: k.kind, Text: squash(statementAround(fbody, m[0], m[1]))})
			}
		}
		if f.name == "constructor" || f.name == "fallback" || f.name == "receive" {
			continue
		}
		if !strings.Contains(f.header, "external") && !strings.Contains(f.header, "public") {
			continue
		}
		gate, party := gateOf(f.header, fbody, mods)
		if m := reInitMod.FindString(f.header); m != "" && party == "anyone" {
			// the first caller of an initializer sets it up: a setup party
			gate, party = squash(m), "deployer"
		}
		powers := map[string]bool{}
		var writes []string
		for _, name := range varNames {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
			for _, m := range re.FindAllStringIndex(fbody, -1) {
				st := squash(statementAround(fbody, m[0], m[1]))
				if op := accessOp(st, name); op == "write" || op == "delete" || op == "push" {
					writes = append(writes, name)
					powers[power(vars[name])] = true
					break
				}
			}
		}
		if reUpgradeFn.MatchString(fbody) || reDelegate.MatchString(fbody) || reSelfDest.MatchString(fbody) || f.name == "_authorizeUpgrade" {
			powers["upgrade"] = true
		}
		if reFunds.MatchString(fbody) {
			powers["funds"] = true
		}
		if reAuthCall.MatchString(fbody) {
			powers["authority"] = true
		}
		if rePauseCall.MatchString(fbody) {
			powers["pause"] = true
		}
		critical := powers["verifier"] || powers["vk"] || powers["authority"] || powers["upgrade"]
		if gate == "none" && !critical {
			continue
		}
		var ps []string
		for p := range powers {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		if len(ps) == 0 {
			ps = []string{"config"}
		}
		res.Privileged = append(res.Privileged, Privileged{File: rel, Line: line, Contract: c.name, Function: f.name,
			Gate: gate, Party: party, Powers: ps, Writes: writes})
		if party != "anyone" {
			name := strings.TrimPrefix(party, "role:")
			src := "sender check in " + f.name
			if gate != "none" && !strings.ContainsAny(gate, "(=") {
				src = "modifier " + gate
			}
			addRole(line, name, roleKind(name), src)
		}
	}
}
