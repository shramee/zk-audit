// Package solidity is a lightweight, dependency-free scanner for the parts of
// Solidity sources that matter to a ZK integration review: verifier
// contracts, proof-verification call sites, public-input array construction,
// and nullifier / root / verifier state. It is a heuristic lexer, not a parser;
// every result carries a line number so a reviewer can check it.
package solidity

import (
	"os"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Verifier is a contract that looks like a generated SNARK verifier.
type Verifier struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	// Kind: gnark-groth16, gnark-plonk, snarkjs-groth16, unknown-verifier.
	Kind string `json:"kind"`
	// NbPublic is the public-input count read from the contract, -1 if unknown.
	NbPublic int `json:"nb_public"`
	// Commitments reports whether a gnark Groth16 verifier handles Pedersen
	// commitments (proof longer than 256 bytes / CommitmentInvalid error).
	Commitments bool `json:"commitments,omitempty"`
}

// VerifyCall is a call site of a proof-verification function.
type VerifyCall struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Contract   string   `json:"contract"`
	Function   string   `json:"function"`
	Callee     string   `json:"callee"`
	Receiver   string   `json:"receiver,omitempty"`
	Args       []string `json:"args"`
	InputArg   string   `json:"input_arg,omitempty"`
	ResultUsed bool     `json:"result_used"`
	Statement  string   `json:"statement"`
}

// InputAssign is one element of a public-input array built before a call.
type InputAssign struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Function string `json:"function"`
	Array    string `json:"array"`
	Index    int    `json:"index"`
	Expr     string `json:"expr"`
}

// StateVar is a contract-level variable relevant to proof consumption.
type StateVar struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Name     string `json:"name"`
	// Kind: nullifier, root, commitment, verifier, vk, nonce.
	Kind string `json:"kind"`
	Decl string `json:"decl"`
}

// StateAccess is a read or write of a StateVar inside a function.
type StateAccess struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	Function string `json:"function"`
	Name     string `json:"name"`
	// Op: write, check, delete, push.
	Op   string `json:"op"`
	Text string `json:"text"`
}

// Result is everything found in a set of files.
type Result struct {
	Files        []string      `json:"files"`
	Verifiers    []Verifier    `json:"verifiers"`
	VerifyCalls  []VerifyCall  `json:"verify_calls"`
	InputAssigns []InputAssign `json:"public_input_assignments"`
	StateVars    []StateVar    `json:"state_vars"`
	StateAccess  []StateAccess `json:"state_accesses"`
	// Privileged, Roles and Upgrades are the trusted-party surfaces
	// (privileged.go).
	Privileged []Privileged `json:"privileged_functions"`
	Roles      []Role       `json:"roles"`
	Upgrades   []Upgrade    `json:"upgrades"`
}

// ScanFiles scans every file; rel names are used in the output.
func ScanFiles(files []fsutil.File) (*Result, error) {
	res := newResult()
	for _, f := range files {
		b, err := os.ReadFile(f.Abs)
		if err != nil {
			return nil, err
		}
		res.Files = append(res.Files, f.Rel)
		scanSource(res, f.Rel, string(b))
	}
	res.sort()
	return res, nil
}

// ScanSource scans one source text (used by tests).
func ScanSource(rel, src string) *Result {
	res := newResult()
	res.Files = []string{rel}
	scanSource(res, rel, src)
	res.sort()
	return res
}

func newResult() *Result {
	return &Result{Files: []string{}, Verifiers: []Verifier{}, VerifyCalls: []VerifyCall{},
		InputAssigns: []InputAssign{}, StateVars: []StateVar{}, StateAccess: []StateAccess{},
		Privileged: []Privileged{}, Roles: []Role{}, Upgrades: []Upgrade{}}
}

func (r *Result) sort() {
	sort.SliceStable(r.VerifyCalls, func(i, j int) bool {
		return less(r.VerifyCalls[i].File, r.VerifyCalls[i].Line, r.VerifyCalls[j].File, r.VerifyCalls[j].Line)
	})
	sort.SliceStable(r.InputAssigns, func(i, j int) bool {
		a, b := r.InputAssigns[i], r.InputAssigns[j]
		if a.File != b.File || a.Function != b.Function || a.Array != b.Array {
			return less(a.File, a.Line, b.File, b.Line)
		}
		return a.Index < b.Index
	})
	sort.SliceStable(r.StateAccess, func(i, j int) bool {
		return less(r.StateAccess[i].File, r.StateAccess[i].Line, r.StateAccess[j].File, r.StateAccess[j].Line)
	})
	sort.SliceStable(r.Privileged, func(i, j int) bool {
		return less(r.Privileged[i].File, r.Privileged[i].Line, r.Privileged[j].File, r.Privileged[j].Line)
	})
	sort.SliceStable(r.Roles, func(i, j int) bool {
		return less(r.Roles[i].File, r.Roles[i].Line, r.Roles[j].File, r.Roles[j].Line)
	})
	sort.SliceStable(r.Upgrades, func(i, j int) bool {
		return less(r.Upgrades[i].File, r.Upgrades[i].Line, r.Upgrades[j].File, r.Upgrades[j].Line)
	})
}

func less(fa string, la int, fb string, lb int) bool {
	if fa != fb {
		return fa < fb
	}
	return la < lb
}

// ---------------------------------------------------------------- lexing

// stripComments blanks out comments but keeps newlines and string contents so
// that byte offsets and line numbers stay valid.
func stripComments(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '"' || b[i] == '\'':
			q := b[i]
			for i++; i < len(b) && b[i] != q && b[i] != '\n'; i++ {
				if b[i] == '\\' {
					i++
				}
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				out[i] = ' '
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				if b[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return string(out)
}

type lineIndex []int

func newLineIndex(s string) lineIndex {
	idx := lineIndex{0}
	for i, c := range s {
		if c == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (l lineIndex) line(off int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > off })
}

// matchClose returns the index of the bracket closing the one at open.
func matchClose(s string, open int) int {
	o := s[open]
	var c byte
	switch o {
	case '{':
		c = '}'
	case '(':
		c = ')'
	case '[':
		c = ']'
	default:
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitArgs splits a call's argument text on top-level commas.
func splitArgs(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// ---------------------------------------------------------------- scanning

var (
	reContract = regexp.MustCompile(`\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)[^{;]*\{`)
	reFunction = regexp.MustCompile(`\b(function\s+([A-Za-z_]\w*)|constructor|fallback|receive|modifier\s+([A-Za-z_]\w*))\s*\(`)
	reVerify   = regexp.MustCompile(`(?:([A-Za-z_][\w]*(?:\s*\([^()]*\))?)\s*\.\s*)?\b(verifyProof|verifyCompressedProof|verifyTx|verify|Verify)\s*\(`)
	reStateVar = regexp.MustCompile(`(?i)(nullif|spent|used|root|commitment|verifier|vkey|vk\b|vkhash|nonce)`)
	reIdent    = regexp.MustCompile(`[A-Za-z_]\w*`)
	reNumber   = regexp.MustCompile(`^\d+$`)
	// a local fixed or dynamic uint array declaration
	reArrDecl = regexp.MustCompile(`\buint(?:256)?\s*\[\s*(\d*)\s*\]\s*(?:memory|calldata|storage)?\s+([A-Za-z_]\w*)\s*(=\s*)?`)
	reAssign  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*=\s*([^;=][^;]*);`)
	reGroth   = regexp.MustCompile(`function\s+verifyProof\s*\(([^)]*)\)`)
	reFixed   = regexp.MustCompile(`uint(?:256)?\s*\[\s*(\d+)\s*\]\s*(?:calldata|memory)\s+\w+\s*$`)
	rePlonkN  = regexp.MustCompile(`VK_NB_PUBLIC_INPUTS\s*=\s*(\d+)`)
)

type block struct {
	name       string
	start, end int // body offsets (inside braces)
	headerLine int
}

func scanSource(res *Result, rel, raw string) {
	src := stripComments(raw)
	li := newLineIndex(src)
	for _, m := range reContract.FindAllStringSubmatchIndex(src, -1) {
		open := m[1] - 1
		close := matchClose(src, open)
		if close < 0 {
			continue
		}
		kind := src[m[2]:m[3]]
		name := src[m[4]:m[5]]
		body := block{name: name, start: open + 1, end: close, headerLine: li.line(m[0])}
		if kind == "interface" {
			continue
		}
		scanContract(res, rel, src, li, body, src[m[0]:m[1]])
	}
}

func scanContract(res *Result, rel, src string, li lineIndex, c block, header string) {
	body := src[c.start:c.end]
	// classify verifier contracts
	isVerifier := false
	if v, ok := classifyVerifier(body); ok {
		v.File, v.Line, v.Contract = rel, c.headerLine, c.name
		res.Verifiers = append(res.Verifiers, v)
		isVerifier = true
	}
	// collect function bodies, and blank them to find contract-level decls
	var fns []sigFn
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
		// find '{' or ';' after the signature
		j := pclose + 1
		for j < len(body) && body[j] != '{' && body[j] != ';' {
			j++
		}
		if j >= len(body) || body[j] == ';' {
			continue
		}
		bclose := matchClose(body, j)
		if bclose < 0 {
			continue
		}
		fns = append(fns, sigFn{name: name, header: body[m[0]:j], headerOff: m[0], start: j + 1, end: bclose})
		for k := m[0]; k <= bclose; k++ {
			if level[k] != '\n' {
				level[k] = ' '
			}
		}
	}
	// state variables: statements at contract level
	stateNames := map[string]string{}
	for _, stmt := range splitStatements(string(level)) {
		text := squash(stmt.text)
		if text == "" {
			continue
		}
		first := strings.Fields(text)[0]
		switch first {
		case "event", "error", "struct", "enum", "using", "pragma", "import", "}", "{":
			continue
		}
		if !reStateVar.MatchString(text) {
			continue
		}
		name := stateVarName(text)
		if name == "" {
			continue
		}
		kind := stateKind(name, text)
		if kind == "" {
			continue
		}
		stateNames[name] = kind
		res.StateVars = append(res.StateVars, StateVar{
			File: rel, Line: li.line(c.start + stmt.off), Contract: c.name, Name: name, Kind: kind, Decl: text,
		})
	}
	if isVerifier {
		// a generated verifier's own internals are not integration call sites
		return
	}
	scanPrivileged(res, rel, src, li, c, header, fns, string(level))
	for _, f := range fns {
		scanFunction(res, rel, src, li, c.name, f.name, c.start+f.start, c.start+f.end, stateNames)
	}
}

type stmt struct {
	off  int
	text string
}

func splitStatements(s string) []stmt {
	var out []stmt
	start := 0
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ';':
			if depth == 0 {
				t := s[start:i]
				off := start + (len(t) - len(strings.TrimLeft(t, " \t\r\n")))
				out = append(out, stmt{off: off, text: strings.TrimSpace(t)})
				start = i + 1
			}
		case '{', '}':
			if depth == 0 {
				start = i + 1
			}
		}
	}
	return out
}

var reDeclName = regexp.MustCompile(`([A-Za-z_]\w*)\s*$`)

var reInit = regexp.MustCompile(`=[^>]`)

func stateVarName(text string) string {
	t := text + " "
	if loc := reInit.FindStringIndex(t); loc != nil {
		t = t[:loc[0]]
	}
	t = strings.TrimSpace(t)
	m := reDeclName.FindStringSubmatch(t)
	if m == nil {
		return ""
	}
	return m[1]
}

func stateKind(name, decl string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "nullif") || strings.Contains(n, "spent") || (strings.Contains(n, "used") && strings.Contains(decl, "mapping")):
		return "nullifier"
	case strings.Contains(n, "root"):
		return "root"
	case strings.Contains(n, "commitment"):
		return "commitment"
	case strings.Contains(n, "verifier"):
		return "verifier"
	case strings.Contains(n, "vkey") || n == "vk" || strings.HasPrefix(n, "vk") || strings.HasSuffix(n, "vk") || strings.Contains(n, "vkhash"):
		return "vk"
	case strings.Contains(n, "nonce"):
		return "nonce"
	}
	return ""
}

func classifyVerifier(body string) (Verifier, bool) {
	v := Verifier{NbPublic: -1}
	switch {
	case strings.Contains(body, "PublicInputNotInField") && strings.Contains(body, "function verifyProof"):
		v.Kind = "gnark-groth16"
		v.Commitments = strings.Contains(body, "CommitmentInvalid")
		if m := reGroth.FindStringSubmatch(body); m != nil {
			args := splitArgs(m[1])
			if len(args) > 0 {
				if n := reFixed.FindStringSubmatch(args[len(args)-1]); n != nil {
					v.NbPublic, _ = strconv.Atoi(n[1])
				}
			}
		}
	case strings.Contains(body, "VK_NB_PUBLIC_INPUTS") && strings.Contains(body, "function Verify"):
		v.Kind = "gnark-plonk"
		if m := rePlonkN.FindStringSubmatch(body); m != nil {
			v.NbPublic, _ = strconv.Atoi(m[1])
		}
	case strings.Contains(body, "function verifyProof") && strings.Contains(body, "checkField") && strings.Contains(body, "_pubSignals"):
		v.Kind = "snarkjs-groth16"
		if m := regexp.MustCompile(`uint\s*\[\s*(\d+)\s*\]\s*calldata\s+_pubSignals`).FindStringSubmatch(body); m != nil {
			v.NbPublic, _ = strconv.Atoi(m[1])
		}
	case strings.Contains(body, "function verifyProof") && (strings.Contains(body, "pairing") || strings.Contains(body, "0x08")):
		v.Kind = "unknown-verifier"
	default:
		return v, false
	}
	return v, true
}

func scanFunction(res *Result, rel, src string, li lineIndex, contract, fname string, start, end int, state map[string]string) {
	body := src[start:end]
	// verification calls
	for _, m := range reVerify.FindAllStringSubmatchIndex(body, -1) {
		paren := m[1] - 1
		pclose := matchClose(body, paren)
		if pclose < 0 {
			continue
		}
		callee := body[m[4]:m[5]]
		recv := ""
		if m[2] >= 0 {
			recv = squash(body[m[2]:m[3]])
		}
		// skip declarations like `function verify(` (handled elsewhere) and
		// event/emit lines
		pre := lineBefore(body, m[0])
		if strings.Contains(pre, "function") || strings.Contains(pre, "emit") || strings.Contains(pre, "event") {
			continue
		}
		args := splitArgs(body[paren+1 : pclose])
		vc := VerifyCall{
			File: rel, Line: li.line(start + m[0]), Contract: contract, Function: fname,
			Callee: callee, Receiver: recv, Args: args,
		}
		if len(args) > 0 {
			vc.InputArg = args[len(args)-1]
		}
		st := statementAround(body, m[0], pclose)
		vc.Statement = squash(st)
		vc.ResultUsed = resultUsed(st, m[0]-strings.LastIndexAny(body[:m[0]], ";{}")-1)
		res.VerifyCalls = append(res.VerifyCalls, vc)
	}
	// public-input arrays: local uint arrays and their element assignments
	arrays := map[string]bool{}
	for _, m := range reArrDecl.FindAllStringSubmatchIndex(body, -1) {
		name := body[m[4]:m[5]]
		arrays[name] = true
		if m[6] >= 0 { // initialised
			rest := strings.TrimSpace(body[m[1]:])
			if strings.HasPrefix(rest, "[") {
				open := m[1] + strings.Index(body[m[1]:], "[")
				close := matchClose(body, open)
				if close > 0 {
					for i, e := range splitArgs(body[open+1 : close]) {
						res.InputAssigns = append(res.InputAssigns, InputAssign{
							File: rel, Line: li.line(start + open), Contract: contract, Function: fname,
							Array: name, Index: i, Expr: squash(e),
						})
					}
				}
			}
		}
	}
	for _, m := range reAssign.FindAllStringSubmatchIndex(body, -1) {
		name := body[m[2]:m[3]]
		if !arrays[name] {
			continue
		}
		idx, _ := strconv.Atoi(body[m[4]:m[5]])
		res.InputAssigns = append(res.InputAssigns, InputAssign{
			File: rel, Line: li.line(start + m[0]), Contract: contract, Function: fname,
			Array: name, Index: idx, Expr: squash(body[m[6]:m[7]]),
		})
	}
	// inline array literal passed straight to a verify call
	for _, vc := range res.VerifyCalls {
		if vc.File != rel || vc.Function != fname || vc.Contract != contract {
			continue
		}
		in := vc.InputArg
		if strings.HasPrefix(in, "[") && strings.HasSuffix(in, "]") {
			for i, e := range splitArgs(in[1 : len(in)-1]) {
				res.InputAssigns = append(res.InputAssigns, InputAssign{
					File: rel, Line: vc.Line, Contract: contract, Function: fname,
					Array: "(inline)", Index: i, Expr: squash(e),
				})
			}
		}
	}
	// state accesses
	for name := range state {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		for _, m := range re.FindAllStringIndex(body, -1) {
			st := squash(statementAround(body, m[0], m[1]))
			op := accessOp(st, name)
			if op == "" {
				continue
			}
			res.StateAccess = append(res.StateAccess, StateAccess{
				File: rel, Line: li.line(start + m[0]), Contract: contract, Function: fname,
				Name: name, Op: op, Text: st,
			})
		}
	}
	dedupAccess(res)
}

func dedupAccess(res *Result) {
	seen := map[string]bool{}
	out := res.StateAccess[:0]
	for _, a := range res.StateAccess {
		k := a.File + "|" + strconv.Itoa(a.Line) + "|" + a.Name + "|" + a.Op
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	res.StateAccess = out
}

func accessOp(st, name string) string {
	switch {
	case strings.HasPrefix(st, "delete ") && strings.Contains(st, name):
		return "delete"
	case regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\.\s*push\s*\(`).MatchString(st):
		return "push"
	case regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*(\[[^\]]*\]\s*)*(=|\+=|-=|\+\+|--)[^=]`).MatchString(st + " "):
		return "write"
	case strings.HasPrefix(st, "require") || strings.HasPrefix(st, "if") || strings.HasPrefix(st, "assert") || strings.Contains(st, "revert"):
		return "check"
	}
	return ""
}

func lineBefore(s string, off int) string {
	i := strings.LastIndexByte(s[:off], '\n')
	return s[i+1 : off]
}

// statementAround returns the statement text containing [from, to).
func statementAround(s string, from, to int) string {
	a := strings.LastIndexAny(s[:from], ";{}") + 1
	b := to
	depth := 0
	for ; b < len(s); b++ {
		switch s[b] {
		case '(':
			depth++
		case ')':
			depth--
		case ';', '{', '}':
			if depth <= 0 {
				return strings.TrimSpace(s[a:b])
			}
		}
	}
	return strings.TrimSpace(s[a:])
}

// resultUsed reports whether the call's return value is consumed. callOff is
// the offset of the call inside st.
func resultUsed(st string, callOff int) bool {
	t := squash(st)
	for _, p := range []string{"require", "assert", "if", "return", "bool ", "while"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if callOff > 0 && callOff <= len(st) {
		pre := st[:callOff]
		if strings.Contains(pre, "=") || strings.Contains(pre, "!") || strings.Contains(pre, "&&") || strings.Contains(pre, "||") || strings.Contains(pre, "(") {
			return true
		}
	}
	return false
}

// MentionsBinding reports which context values an expression mentions.
func MentionsBinding(expr string) []string {
	var out []string
	checks := []struct{ needle, tag string }{
		{"msg.sender", "sender"}, {"tx.origin", "origin"}, {"block.chainid", "chainid"},
		{"address(this)", "contract"}, {"nonce", "nonce"}, {"epoch", "epoch"},
		{"recipient", "recipient"}, {"deadline", "deadline"},
	}
	l := strings.ToLower(expr)
	for _, c := range checks {
		if strings.Contains(l, strings.ToLower(c.needle)) {
			out = append(out, c.tag)
		}
	}
	return out
}

// Idents returns identifiers in an expression (used to link inputs to state).
func Idents(expr string) []string { return reIdent.FindAllString(expr, -1) }

// IsNumber reports whether s is a decimal literal.
func IsNumber(s string) bool { return reNumber.MatchString(s) }
