package solidity

import (
	"regexp"
	"strings"
)

// Contract is a contract, abstract contract, library or interface found in
// a scanned file, or in a file one of them imports (Peripheral).
type Contract struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Name string `json:"name"`
	// Kind: contract, abstract, library, interface.
	Kind      string     `json:"kind"`
	Bases     []string   `json:"bases,omitempty"`
	Functions []Function `json:"functions"`
	// Using lists `using L for T` directives as "L for T".
	Using []string `json:"using,omitempty"`
	// Peripheral contracts come from imported files outside the scan (a
	// Foundry lib/, node_modules); they are read for inheritance and types
	// only and listed when a scanned contract refers to them.
	Peripheral bool `json:"peripheral,omitempty"`
	// Verifier is set when the contract is a SNARK verifier (see Verifier).
	Verifier bool `json:"verifier,omitempty"`
}

// Function is one function header.
type Function struct {
	Name       string   `json:"name"`
	Line       int      `json:"line"`
	Params     []Param  `json:"params"`
	Returns    []Param  `json:"returns,omitempty"`
	Visibility string   `json:"visibility,omitempty"`
	Mutability string   `json:"mutability,omitempty"`
	Modifiers  []string `json:"modifiers,omitempty"`
	// Signature is the canonical ABI signature (`name(uint256[8],bytes)`)
	// and Selector its first four Keccak-256 bytes; both are empty when a
	// parameter type cannot be mapped to an ABI type (a struct).
	Signature string `json:"signature,omitempty"`
	Selector  string `json:"selector,omitempty"`
	HasBody   bool   `json:"has_body"`
}

// Param is one parameter or return value.
type Param struct {
	// Type is the declared type without data location (`uint256[8]`,
	// `bytes`, `IVerifier`).
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// unit is one parsed contract with everything the second scan phase needs.
type unit struct {
	file       string
	raw        string // the file with comments
	src        string // the file without comments
	li         lineIndex
	kind, name string
	header     string
	blk        block
	bases      []string
	fns        []sigFn
	level      string            // body with function bodies blanked
	vars       map[string]string // contract-level variable -> declared type
	consts     map[string]string // constant / immutable -> initialiser
	using      []usingDir
	peripheral bool
	info       *Contract
}

type usingDir struct{ lib, typ string }

var (
	reUsing   = regexp.MustCompile(`^using\s+([A-Za-z_][\w.]*)\s+for\s+([^;]+?)(?:\s+global)?$`)
	reFnHead  = regexp.MustCompile(`^(?:function\s+([A-Za-z_]\w*)|constructor|fallback|receive|modifier\s+([A-Za-z_]\w*))\s*\(`)
	reVisib   = regexp.MustCompile(`\b(external|public|internal|private)\b`)
	reMutab   = regexp.MustCompile(`\b(view|pure|payable)\b`)
	reModCall = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*(\([^()]*\))?`)
)

// headerWords are the keywords that can follow a function's parameter list
// and are not modifiers.
var headerWords = map[string]bool{
	"external": true, "public": true, "internal": true, "private": true, "view": true, "pure": true,
	"payable": true, "virtual": true, "override": true, "returns": true, "nonpayable": true, "constant": true,
}

// parseFile splits one file into contract units.
func parseFile(rel, raw string, peripheral bool) []*unit {
	src := stripComments(raw)
	li := newLineIndex(src)
	var out []*unit
	for _, m := range reContract.FindAllStringSubmatchIndex(src, -1) {
		open := m[1] - 1
		close := matchClose(src, open)
		if close < 0 {
			continue
		}
		kind := src[m[2]:m[3]]
		if kind == "contract" && strings.HasPrefix(strings.TrimSpace(src[m[0]:m[2]]), "abstract") {
			kind = "abstract"
		}
		u := &unit{file: rel, raw: raw, src: src, li: li, kind: kind, name: src[m[4]:m[5]], header: src[m[0]:m[1]],
			blk: block{name: src[m[4]:m[5]], start: open + 1, end: close, headerLine: li.line(m[0])}, peripheral: peripheral,
			vars: map[string]string{}, consts: map[string]string{}}
		u.bases = inheritance(u.header)
		u.parseBody()
		out = append(out, u)
	}
	return out
}

// parseBody collects function headers and bodies, blanks them to find
// contract-level statements, and records variables and using directives.
func (u *unit) parseBody() {
	body := u.src[u.blk.start:u.blk.end]
	level := []byte(body)
	for _, m := range reFunction.FindAllStringSubmatchIndex(body, -1) {
		name := "constructor"
		switch {
		case m[4] >= 0:
			name = body[m[4]:m[5]]
		case m[6] >= 0:
			name = "modifier " + body[m[6]:m[7]]
		default:
			name = strings.Fields(body[m[2]:m[3]])[0]
		}
		paren := m[1] - 1
		pclose := matchClose(body, paren)
		if pclose < 0 {
			continue
		}
		j := pclose + 1
		for j < len(body) && body[j] != '{' && body[j] != ';' {
			j++
		}
		if j >= len(body) {
			continue
		}
		f := sigFn{name: name, header: body[m[0]:j], headerOff: m[0], params: body[paren+1 : pclose], after: body[pclose+1 : j]}
		if body[j] == ';' {
			// a declaration without body (interface, abstract)
			f.start, f.end = -1, -1
			for k := m[0]; k <= j; k++ {
				if level[k] != '\n' {
					level[k] = ' '
				}
			}
			u.fns = append(u.fns, f)
			continue
		}
		bclose := matchClose(body, j)
		if bclose < 0 {
			continue
		}
		f.start, f.end = j+1, bclose
		u.fns = append(u.fns, f)
		for k := m[0]; k <= bclose; k++ {
			if level[k] != '\n' {
				level[k] = ' '
			}
		}
	}
	u.level = string(level)
	for _, st := range splitStatements(u.level) {
		text := squash(st.text)
		if text == "" {
			continue
		}
		first := strings.Fields(text)[0]
		switch first {
		case "event", "error", "struct", "enum", "pragma", "import", "}", "{", "modifier", "function":
			continue
		case "using":
			if m := reUsing.FindStringSubmatch(text); m != nil {
				u.using = append(u.using, usingDir{lib: m[1], typ: strings.TrimSpace(m[2])})
			}
			continue
		}
		name := stateVarName(text)
		if name == "" {
			continue
		}
		decl := text
		init := ""
		if loc := reInit.FindStringIndex(text + " "); loc != nil {
			decl = strings.TrimSpace(text[:loc[0]])
			init = strings.TrimSpace(text[loc[0]+1:])
		}
		typ := declType(decl, name)
		if typ == "" {
			continue
		}
		u.vars[name] = typ
		if strings.Contains(" "+decl+" ", " constant ") || strings.Contains(" "+decl+" ", " immutable ") {
			u.consts[name] = init
		}
	}
}

// declType returns the type part of a declaration `T [modifiers] name`.
func declType(decl, name string) string {
	d := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(decl), name))
	if strings.HasPrefix(d, "mapping") {
		if i := strings.Index(d, "("); i >= 0 {
			if j := matchClose(d, i); j > 0 {
				return squash(d[:j+1])
			}
		}
		return d
	}
	fs := strings.Fields(d)
	if len(fs) == 0 {
		return ""
	}
	t := fs[0]
	// `address payable`, `uint256 [ 2 ]`
	rest := fs[1:]
	for len(rest) > 0 && (strings.HasPrefix(rest[0], "[") || rest[0] == "payable") {
		if rest[0] != "payable" {
			t += rest[0]
		}
		rest = rest[1:]
	}
	return strings.ReplaceAll(t, " ", "")
}

// parseParams parses a parameter list `uint256[8] calldata proof, bytes p`.
func parseParams(s string) []Param {
	var out []Param
	for _, p := range splitArgs(s) {
		fs := strings.Fields(p)
		if len(fs) == 0 {
			continue
		}
		var typ []string
		name := ""
		for i, f := range fs {
			switch f {
			case "memory", "calldata", "storage", "payable", "indexed":
				continue
			}
			if i > 0 && i == len(fs)-1 && reIdent.MatchString(f) && !strings.ContainsAny(f, "[]()") && isIdentOnly(f) {
				name = f
				continue
			}
			typ = append(typ, f)
		}
		t := strings.Join(typ, "")
		if strings.HasPrefix(t, "mapping") {
			t = strings.Join(typ, " ")
		}
		out = append(out, Param{Type: t, Name: name})
	}
	return out
}

func isIdentOnly(s string) bool {
	m := reIdent.FindString(s)
	return m == s
}

// header parses a function's after-parameter text: visibility, mutability,
// modifiers and the returns list.
func parseAfter(after string) (vis, mut string, mods []string, rets []Param) {
	a := after
	if i := strings.Index(a, "returns"); i >= 0 {
		if o := strings.Index(a[i:], "("); o >= 0 {
			open := i + o
			if c := matchClose(a, open); c > 0 {
				rets = parseParams(a[open+1 : c])
				a = a[:i] + a[c+1:]
			}
		}
	}
	if m := reVisib.FindString(a); m != "" {
		vis = m
	}
	if m := reMutab.FindString(a); m != "" {
		mut = m
	}
	for _, m := range reModCall.FindAllStringSubmatch(a, -1) {
		w := m[1]
		if headerWords[w] {
			continue
		}
		mods = append(mods, strings.TrimSpace(m[0]))
	}
	return
}

// elementary ABI types and their canonical names.
var reElem = regexp.MustCompile(`^(u?int)(\d*)$|^(bytes)(\d*)$|^(address|bool|string|byte)$`)

// abiType maps a declared type to its canonical ABI type, or "" when it
// cannot (structs, function types, mappings). contracts names every known
// contract, interface and library; enums map to uint8.
func abiType(t string, contracts map[string]*unit, enums map[string]bool) string {
	base, dims := t, ""
	if i := strings.Index(t, "["); i >= 0 {
		base, dims = t[:i], t[i:]
	}
	base = strings.TrimSpace(base)
	if m := reElem.FindStringSubmatch(base); m != nil {
		switch {
		case m[1] != "":
			if m[2] == "" {
				return m[1] + "256" + dims
			}
			return base + dims
		case m[3] != "":
			return base + dims
		case m[5] == "byte":
			return "bytes1" + dims
		default:
			return base + dims
		}
	}
	// qualified names: I.Struct, Lib.Enum
	short := base
	if i := strings.LastIndex(base, "."); i >= 0 {
		short = base[i+1:]
	}
	if enums[short] {
		return "uint8" + dims
	}
	if _, ok := contracts[short]; ok {
		return "address" + dims
	}
	return ""
}
