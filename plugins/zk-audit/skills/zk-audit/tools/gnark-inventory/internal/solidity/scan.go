// Package solidity is a lightweight, dependency-free scanner for the parts of
// Solidity sources that matter to a ZK integration review: verifier
// contracts, proof-verification call sites, public-input array construction,
// nullifier / root / verifier state, privileged functions and the entry
// points of every contract. It is a heuristic lexer, not a parser; every
// result carries a line number so a reviewer can check it.
//
// The scan runs in two phases. The first splits every file into contracts
// (with their bases, function headers, variables and `using` directives) and
// follows `import` directives, with remappings, into files outside the scan
// (a Foundry lib/), which are read as peripheral contracts. The second phase
// resolves inheritance (modifiers and state declared in a base, a
// verification call made in a base contract), the declared type of each
// call's receiver (interface, contract, library, `using ... for`), low-level
// calls built with abi.encodeWithSelector / encodeWithSignature /
// encodeCall, and maps every call site to the verifier contracts it can
// reach.
package solidity

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/keccak"
)

// Verifier is a contract or library that looks like a SNARK verifier.
type Verifier struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Contract string `json:"contract"`
	// Kind: gnark-groth16, gnark-plonk, snarkjs-groth16, snarkjs-plonk,
	// snarkjs-fflonk, zokrates-groth16, noir-barretenberg, halo2, sp1,
	// risc0, custom (hand-written or unknown generator).
	Kind string `json:"kind"`
	// Generator: gnark, snarkjs, zokrates, barretenberg, halo2, sp1, risc0,
	// hand-written.
	Generator string `json:"generator"`
	// Template names the generator template the source matches, when the
	// tool recognises it.
	Template string `json:"template,omitempty"`
	// Marker is the generator's "do not edit" banner when the file has it.
	Marker string `json:"marker,omitempty"`
	// NbPublic is the public-input count read from the contract, -1 if unknown.
	NbPublic int `json:"nb_public"`
	// Commitments reports whether a gnark Groth16 verifier handles Pedersen
	// commitments (CommitmentInvalid error).
	Commitments bool `json:"commitments,omitempty"`
	// Precompiles lists the BN254 precompiles the source names.
	Precompiles []string `json:"precompiles,omitempty"`
	Library     bool     `json:"library,omitempty"`
}

// FnRef is the function a call site reaches, as declared on the receiver's
// type (an interface, a contract or a library).
type FnRef struct {
	Contract  string  `json:"contract"`
	Kind      string  `json:"kind"`
	Function  string  `json:"function"`
	Signature string  `json:"signature,omitempty"`
	Selector  string  `json:"selector,omitempty"`
	Params    []Param `json:"params"`
	Returns   []Param `json:"returns,omitempty"`
	File      string  `json:"file"`
	Line      int     `json:"line"`
	// Overloads counts other functions of the same name and arity.
	Overloads int `json:"overloads,omitempty"`
}

// VerifierRef is a verifier contract a call site can reach.
type VerifierRef struct {
	Contract string `json:"contract"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	// Match: direct (the receiver's type is the verifier), inherits (the
	// verifier inherits the receiver's interface), selector (same canonical
	// signature), name-only (same function name, different parameters),
	// inherited-call (the caller inherits the verifier).
	Match string `json:"match"`
}

// LowLevel describes a verification made with address.staticcall/call.
type LowLevel struct {
	Kind string `json:"kind"`
	// Encoding: encodeWithSelector, encodeWithSignature, encodeCall.
	Encoding       string `json:"encoding"`
	SelectorExpr   string `json:"selector_expr"`
	Signature      string `json:"signature,omitempty"`
	Selector       string `json:"selector,omitempty"`
	SuccessVar     string `json:"success_var,omitempty"`
	SuccessChecked bool   `json:"success_checked"`
	ReturnVar      string `json:"return_var,omitempty"`
	DecodesBool    bool   `json:"decodes_bool"`
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
	// Via: external (a typed receiver), cast (`IVerifier(addr).f`), library
	// (`Lib.f`), using (`x.f` through `using Lib for T`), internal (own or
	// inherited function), inherited (the contract inherits the verifier),
	// staticcall, call, address (receiver typed as a bare address).
	Via          string        `json:"via"`
	ReceiverType string        `json:"receiver_type,omitempty"`
	Target       *FnRef        `json:"target,omitempty"`
	Verifiers    []VerifierRef `json:"verifiers,omitempty"`
	// InheritedBy lists contracts that inherit the calling contract, when
	// the call is made in a base contract.
	InheritedBy []string  `json:"inherited_by,omitempty"`
	LowLevel    *LowLevel `json:"low_level,omitempty"`
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
	// Contracts lists every contract, library and interface of the scanned
	// files, and the peripheral ones a scanned contract refers to.
	Contracts []Contract `json:"contracts"`
	// EntryPoints are the external and public state-changing functions of
	// every non-verifier contract (entry.go): the contract-review surface.
	EntryPoints []EntryPoint `json:"entry_points"`
	Imports     []Import     `json:"imports"`
	Remappings  []Remapping  `json:"remappings,omitempty"`
	// Notes are scan limitations worth showing (unresolved bases, duplicate
	// contract names).
	Notes []string `json:"notes,omitempty"`
}

// Options for Scan.
type Options struct {
	// Root is the repository root. With it, imports are resolved (with
	// Remappings) and imported files outside the scan are read as
	// peripheral contracts.
	Root       string
	Remappings []Remapping
}

// maxPeripheral bounds the imported files read outside the scan.
const maxPeripheral = 400

// Scan scans files; Rel names are used in the output.
func Scan(files []fsutil.File, opt Options) (*Result, error) {
	s := newScanner()
	s.res.Remappings = opt.Remappings
	srcs := map[string]string{}
	var order []string
	for _, f := range files {
		b, err := os.ReadFile(f.Abs)
		if err != nil {
			return nil, err
		}
		srcs[f.Rel] = string(b)
		order = append(order, f.Rel)
	}
	exists := func(rel string) bool { _, ok := srcs[rel]; return ok }
	read := func(string) (string, bool) { return "", false }
	if opt.Root != "" {
		exists = func(rel string) bool {
			if _, ok := srcs[rel]; ok {
				return true
			}
			st, err := os.Stat(filepath.Join(opt.Root, filepath.FromSlash(rel)))
			return err == nil && st.Mode().IsRegular()
		}
		read = func(rel string) (string, bool) {
			b, err := os.ReadFile(filepath.Join(opt.Root, filepath.FromSlash(rel)))
			return string(b), err == nil
		}
	}
	s.run(order, srcs, opt.Remappings, exists, read)
	return s.res, nil
}

// ScanFiles scans files without import resolution.
func ScanFiles(files []fsutil.File) (*Result, error) { return Scan(files, Options{}) }

// ScanSource scans one source text (used by tests).
func ScanSource(rel, src string) *Result { return ScanSources(map[string]string{rel: src}) }

// ScanSources scans several in-memory files; imports resolve among them.
func ScanSources(files map[string]string) *Result {
	var order []string
	for k := range files {
		order = append(order, k)
	}
	sort.Strings(order)
	s := newScanner()
	exists := func(rel string) bool { _, ok := files[rel]; return ok }
	s.run(order, files, nil, exists, func(string) (string, bool) { return "", false })
	return s.res
}

func newResult() *Result {
	return &Result{Files: []string{}, Verifiers: []Verifier{}, VerifyCalls: []VerifyCall{},
		InputAssigns: []InputAssign{}, StateVars: []StateVar{}, StateAccess: []StateAccess{},
		Privileged: []Privileged{}, Roles: []Role{}, Upgrades: []Upgrade{}, Contracts: []Contract{},
		EntryPoints: []EntryPoint{}, Imports: []Import{}}
}

type scanner struct {
	res    *Result
	units  []*unit
	byName map[string]*unit
	enums  map[string]bool
	// referenced peripheral contracts to list
	used map[string]bool
}

func newScanner() *scanner {
	return &scanner{res: newResult(), byName: map[string]*unit{}, enums: map[string]bool{}, used: map[string]bool{}}
}

var reEnum = regexp.MustCompile(`\benum\s+([A-Za-z_]\w*)\s*\{`)

func (s *scanner) add(rel, raw string, peripheral bool) []Import {
	us := parseFile(rel, raw, peripheral)
	for _, u := range us {
		s.units = append(s.units, u)
		if prev, ok := s.byName[u.name]; ok {
			if !prev.peripheral && !peripheral && prev.file != u.file {
				s.res.Notes = append(s.res.Notes, "contract "+u.name+" is declared in both "+prev.file+" and "+u.file+"; types resolve to the first")
			}
			if prev.peripheral && !peripheral {
				s.byName[u.name] = u
			}
			continue
		}
		s.byName[u.name] = u
	}
	src := stripComments(raw)
	for _, m := range reEnum.FindAllStringSubmatch(src, -1) {
		s.enums[m[1]] = true
	}
	return importsOf(rel, src, newLineIndex(src))
}

func (s *scanner) run(order []string, srcs map[string]string, remaps []Remapping, exists func(string) bool, read func(string) (string, bool)) {
	loaded := map[string]bool{}
	var queue []Import
	for _, rel := range order {
		loaded[rel] = true
		s.res.Files = append(s.res.Files, rel)
		imps := s.add(rel, srcs[rel], false)
		for i := range imps {
			imps[i].Resolved, imps[i].Via = resolveImport(rel, imps[i].Path, remaps, exists)
		}
		s.res.Imports = append(s.res.Imports, imps...)
		queue = append(queue, imps...)
	}
	// follow imports into files outside the scan
	n := 0
	for len(queue) > 0 && n < maxPeripheral {
		imp := queue[0]
		queue = queue[1:]
		if imp.Resolved == "" || loaded[imp.Resolved] {
			continue
		}
		loaded[imp.Resolved] = true
		raw, ok := read(imp.Resolved)
		if !ok {
			continue
		}
		n++
		for _, sub := range s.add(imp.Resolved, raw, true) {
			sub.Resolved, sub.Via = resolveImport(imp.Resolved, sub.Path, remaps, exists)
			queue = append(queue, sub)
		}
	}
	s.phase2()
	s.res.sort()
}

// bases returns the transitive base contracts of u, nearest first.
func (s *scanner) bases(u *unit) []*unit {
	var out []*unit
	seen := map[string]bool{u.name: true}
	q := append([]string{}, u.bases...)
	for len(q) > 0 {
		b := q[0]
		q = q[1:]
		if seen[b] {
			continue
		}
		seen[b] = true
		if bu, ok := s.byName[b]; ok {
			out = append(out, bu)
			q = append(q, bu.bases...)
		}
	}
	return out
}

// derived returns the contracts that inherit u, directly or not.
func (s *scanner) derived(u *unit) []string {
	var out []string
	for _, o := range s.units {
		if o == u || o.peripheral {
			continue
		}
		for _, b := range s.bases(o) {
			if b == u {
				out = append(out, o.name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *scanner) phase2() {
	// contract infos (functions with ABI signatures)
	for _, u := range s.units {
		c := &Contract{File: u.file, Line: u.blk.headerLine, Name: u.name, Kind: u.kind, Bases: u.bases, Functions: []Function{}, Peripheral: u.peripheral}
		for _, ud := range u.using {
			c.Using = append(c.Using, ud.lib+" for "+ud.typ)
		}
		body := u.src[u.blk.start:u.blk.end]
		for _, f := range u.fns {
			if strings.HasPrefix(f.name, "modifier ") {
				continue
			}
			fn := Function{Name: f.name, Line: u.li.line(u.blk.start + f.headerOff), Params: parseParams(f.params), HasBody: f.start >= 0}
			fn.Visibility, fn.Mutability, fn.Modifiers, fn.Returns = parseAfter(f.after)
			if u.kind == "interface" && fn.Visibility == "" {
				fn.Visibility = "external"
			}
			fn.Signature = s.signature(fn)
			if fn.Signature != "" {
				fn.Selector = keccak.Selector(fn.Signature)
			}
			c.Functions = append(c.Functions, fn)
		}
		u.info = c
		if u.peripheral || u.kind == "interface" {
			continue
		}
		if v, ok := classifyVerifier(u.name, body, u.raw[u.blk.start:u.blk.end], u.raw); ok {
			v.File, v.Line, v.Contract, v.Library = u.file, u.blk.headerLine, u.name, u.kind == "library"
			s.res.Verifiers = append(s.res.Verifiers, v)
			c.Verifier = true
		}
	}
	// unresolved bases
	for _, u := range s.units {
		if u.peripheral {
			continue
		}
		for _, b := range u.bases {
			if bu, ok := s.byName[b]; !ok {
				s.res.Notes = append(s.res.Notes, u.file+": "+u.name+" inherits "+b+", which is not in the scanned or imported files; its modifiers and state are unknown")
			} else if bu.peripheral {
				s.used[b] = true
			}
		}
	}
	for _, u := range s.units {
		if u.peripheral || u.kind == "interface" {
			continue
		}
		s.scanUnit(u)
	}
	s.resolveCalls()
	for _, u := range s.units {
		if !u.peripheral || s.used[u.name] {
			s.res.Contracts = append(s.res.Contracts, *u.info)
		}
	}
	dedupAccess(s.res)
}

// signature returns the canonical ABI signature of fn, or "".
func (s *scanner) signature(fn Function) string {
	var ts []string
	for _, p := range fn.Params {
		t := abiType(p.Type, s.byName, s.enums)
		if t == "" {
			return ""
		}
		ts = append(ts, t)
	}
	switch fn.Name {
	case "constructor", "fallback", "receive":
		return ""
	}
	return fn.Name + "(" + strings.Join(ts, ",") + ")"
}

func (s *scanner) scanUnit(u *unit) {
	rel, li, c := u.file, u.li, u.blk
	stateNames := map[string]string{}
	for _, st := range splitStatements(u.level) {
		text := squash(st.text)
		if text == "" {
			continue
		}
		switch strings.Fields(text)[0] {
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
		s.res.StateVars = append(s.res.StateVars, StateVar{
			File: rel, Line: li.line(c.start + st.off), Contract: c.name, Name: name, Kind: kind, Decl: text,
		})
	}
	if u.info.Verifier {
		// a generated verifier's own internals are not integration call sites
		return
	}
	// proof-related state declared in base contracts is accessed here too
	for _, b := range s.bases(u) {
		for name, typ := range b.vars {
			if _, ok := stateNames[name]; ok {
				continue
			}
			if k := stateKind(name, typ+" "+name); k != "" {
				stateNames[name] = k
			}
		}
	}
	mods := s.modParties(u)
	allBases := append([]string{}, u.bases...)
	baseVars := map[string]string{}
	for _, b := range s.bases(u) {
		for _, n := range b.bases {
			allBases = appendUniqStr(allBases, n)
		}
		for name, typ := range b.vars {
			if _, isConst := b.consts[name]; !isConst {
				if _, ok := baseVars[name]; !ok {
					baseVars[name] = typ
				}
			}
		}
	}
	scanPrivileged(s.res, u, mods, allBases, baseVars)
	for _, f := range u.fns {
		if f.start < 0 || strings.HasPrefix(f.name, "modifier ") {
			continue
		}
		s.scanFunction(u, f, stateNames)
	}
	s.entryPoints(u, mods)
}

// modParties maps every modifier visible in u (its own and its bases') to
// the party its sender check names ("" when it has none).
func (s *scanner) modParties(u *unit) map[string]string {
	mods := map[string]string{}
	chain := append([]*unit{u}, s.bases(u)...)
	for _, x := range chain {
		body := x.src[x.blk.start:x.blk.end]
		for _, f := range x.fns {
			if !strings.HasPrefix(f.name, "modifier ") || f.start < 0 {
				continue
			}
			name := strings.TrimPrefix(f.name, "modifier ")
			if _, ok := mods[name]; ok {
				continue
			}
			mods[name] = modifierParty(body[f.start:f.end])
		}
	}
	return mods
}

var (
	reStateVar = regexp.MustCompile(`(?i)(nullif|spent|used|root|commitment|verifier|vkey|vk\b|vkhash|nonce)`)
	reIdent    = regexp.MustCompile(`[A-Za-z_]\w*`)
	reNumber   = regexp.MustCompile(`^\d+$`)
	reContract = regexp.MustCompile(`\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)[^{;]*\{`)
	reFunction = regexp.MustCompile(`\b(function\s+([A-Za-z_]\w*)|constructor|fallback|receive|modifier\s+([A-Za-z_]\w*))\s*\(`)
	reVerify   = regexp.MustCompile(`(?:([A-Za-z_][\w]*(?:\s*\[[^\[\]]*\])*(?:\s*\([^()]*\))?(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*)?\b(verifyProof|verifyCompressedProof|verifyTx|verify|Verify)\s*\(`)
	reLowCall  = regexp.MustCompile(`([A-Za-z_][\w.]*(?:\s*\([^()]*\))?(?:\s*\[[^\[\]]*\])*)\s*\.\s*(staticcall|call)\s*(?:\{[^}]*\})?\s*\(`)
	reVerifyNm = regexp.MustCompile(`^(verifyProof|verifyCompressedProof|verifyTx|verify|Verify)$`)
	// a local fixed or dynamic uint array declaration
	reArrDecl = regexp.MustCompile(`\buint(?:256)?\s*\[\s*(\d*)\s*\]\s*(?:memory|calldata|storage)?\s+([A-Za-z_]\w*)\s*(=\s*)?`)
	reAssign  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*=\s*([^;=][^;]*);`)
)

type block struct {
	name       string
	start, end int // body offsets (inside braces)
	headerLine int
}

func (s *scanner) scanFunction(u *unit, f sigFn, state map[string]string) {
	rel, src, li, contract, fname := u.file, u.src, u.li, u.name, f.name
	start, end := u.blk.start+f.start, u.blk.start+f.end
	body := src[start:end]
	code := blankStrings(body)
	res := s.res
	nCalls := len(res.VerifyCalls)
	// high-level verification calls
	for _, m := range reVerify.FindAllStringSubmatchIndex(code, -1) {
		paren := m[1] - 1
		pclose := matchClose(code, paren)
		if pclose < 0 {
			continue
		}
		callee := code[m[4]:m[5]]
		recv := ""
		if m[2] >= 0 {
			recv = squash(code[m[2]:m[3]])
		}
		pre := lineBefore(code, m[0])
		if strings.Contains(pre, "function") || strings.Contains(pre, "emit") || strings.Contains(pre, "event") {
			continue
		}
		if strings.HasPrefix(recv, "abi.") || recv == "abi" {
			continue
		}
		args := splitArgs(body[paren+1 : pclose])
		vc := VerifyCall{File: rel, Line: li.line(start + m[0]), Contract: contract, Function: fname,
			Callee: callee, Receiver: recv, Args: args}
		if len(args) > 0 {
			vc.InputArg = args[len(args)-1]
		}
		st := statementAround(body, m[0], pclose)
		vc.Statement = squash(st)
		vc.ResultUsed = resultUsed(st, m[0]-strings.LastIndexAny(body[:m[0]], ";{}")-1)
		s.typeCall(u, f, body, &vc)
		if vc.Via == "skip" {
			continue
		}
		res.VerifyCalls = append(res.VerifyCalls, vc)
	}
	// low-level verification calls
	for _, m := range reLowCall.FindAllStringSubmatchIndex(code, -1) {
		paren := m[1] - 1
		pclose := matchClose(code, paren)
		if pclose < 0 {
			continue
		}
		vc, ok := s.lowLevel(u, f, body, code, code[m[2]:m[3]], code[m[4]:m[5]], m[0], paren, pclose)
		if !ok {
			continue
		}
		vc.File, vc.Line, vc.Contract, vc.Function = rel, li.line(start+m[0]), contract, fname
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
	for _, vc := range res.VerifyCalls[nCalls:] {
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
	var names []string
	for name := range state {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		for _, m := range re.FindAllStringIndex(code, -1) {
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
}

var reCast = regexp.MustCompile(`^([A-Za-z_]\w*)\s*\((.*)\)$`)

// typeCall sets Via, ReceiverType and Target of a high-level call. It sets
// Via to "skip" for a call that is not a verification (a non-verifier
// library or contract function named verify, an internal helper that is
// not a verifier).
func (s *scanner) typeCall(u *unit, f sigFn, body string, vc *VerifyCall) {
	recv := vc.Receiver
	nargs := len(vc.Args)
	if recv == "" {
		// own or inherited function
		for _, x := range append([]*unit{u}, s.bases(u)...) {
			if fr := s.findFn(x, vc.Callee, nargs); fr != nil {
				vc.Target = fr
				if x != u && x.info != nil && x.info.Verifier {
					vc.Via = "inherited"
					vc.ReceiverType = x.name
					return
				}
				vc.Via = "internal"
				vc.ReceiverType = x.name
				return
			}
		}
		// unknown target (a base outside the scan): keep it, unresolved
		vc.Via = "internal"
		return
	}
	if recv == "this" {
		vc.Via, vc.ReceiverType = "external", u.name
		vc.Target = s.findFnChain(u, vc.Callee, nargs)
		return
	}
	if m := reCast.FindStringSubmatch(recv); m != nil {
		if m[1] == "address" || m[1] == "payable" {
			vc.Via = "address"
			return
		}
		if _, ok := s.byName[m[1]]; ok {
			vc.Via, vc.ReceiverType = "cast", m[1]
			vc.Target = s.findFnChain(s.byName[m[1]], vc.Callee, nargs)
			s.markUsed(m[1])
			return
		}
	}
	if x, ok := s.byName[recv]; ok {
		vc.ReceiverType = recv
		s.markUsed(recv)
		if x.kind == "library" {
			vc.Via = "library"
		} else {
			vc.Via = "external"
		}
		vc.Target = s.findFnChain(x, vc.Callee, nargs)
		if x.kind == "library" && (vc.Target == nil || (x.info != nil && !x.info.Verifier && !strings.Contains(strings.ToLower(recv), "verif"))) {
			// MerkleProof.verify, a signature library's verify: not a proof verifier
			vc.Via = "skip"
		}
		return
	}
	typ := s.varType(u, f, body, recv)
	if typ == "" {
		vc.Via = "external"
		return
	}
	vc.ReceiverType = typ
	if typ == "address" || typ == "addresspayable" {
		vc.Via = "address"
		return
	}
	if x, ok := s.byName[typ]; ok && x.kind != "library" {
		vc.Via = "external"
		s.markUsed(typ)
		vc.Target = s.findFnChain(x, vc.Callee, nargs)
		return
	}
	// using L for T
	for _, x := range append([]*unit{u}, s.bases(u)...) {
		for _, ud := range x.using {
			if ud.typ == typ || ud.typ == "*" {
				if lu, ok := s.byName[ud.lib]; ok {
					if fr := s.findFnChain(lu, vc.Callee, nargs+1); fr != nil {
						vc.Via, vc.ReceiverType, vc.Target = "using", ud.lib, fr
						s.markUsed(ud.lib)
						return
					}
				}
			}
		}
	}
	vc.Via = "external"
}

func (s *scanner) markUsed(name string) {
	if x, ok := s.byName[name]; ok && x.peripheral {
		s.used[name] = true
	}
}

// findFnChain looks for the function in x and its bases.
func (s *scanner) findFnChain(x *unit, name string, nargs int) *FnRef {
	for _, y := range append([]*unit{x}, s.bases(x)...) {
		if fr := s.findFn(y, name, nargs); fr != nil {
			return fr
		}
	}
	return nil
}

// findFn returns the function of x with that name and arity (the first of
// several overloads, with Overloads counting the others).
func (s *scanner) findFn(x *unit, name string, nargs int) *FnRef {
	if x.info == nil {
		return nil
	}
	var hit *FnRef
	n := 0
	for _, fn := range x.info.Functions {
		if fn.Name != name || len(fn.Params) != nargs {
			continue
		}
		n++
		if hit == nil {
			hit = &FnRef{Contract: x.name, Kind: x.kind, Function: fn.Name, Signature: fn.Signature, Selector: fn.Selector,
				Params: fn.Params, Returns: fn.Returns, File: x.file, Line: fn.Line}
		}
	}
	if hit != nil {
		hit.Overloads = n - 1
	}
	return hit
}

var reIndexSuffix = regexp.MustCompile(`\s*\[[^\[\]]*\]\s*$`)

// varType returns the declared type of a receiver expression: a parameter,
// a local, or a state variable of u or its bases. Mapping and array
// elements give their value type.
func (s *scanner) varType(u *unit, f sigFn, body, expr string) string {
	e := strings.TrimSpace(expr)
	indexed := 0
	for reIndexSuffix.MatchString(e) {
		e = reIndexSuffix.ReplaceAllString(e, "")
		indexed++
	}
	if strings.Contains(e, ".") || !isIdentOnly(e) {
		return ""
	}
	typ := ""
	for _, p := range parseParams(f.params) {
		if p.Name == e {
			typ = p.Type
		}
	}
	if typ == "" {
		re := regexp.MustCompile(`\b([A-Za-z_][\w.]*(?:\s*\[\s*\d*\s*\])*)\s+(?:memory\s+|calldata\s+|storage\s+)?` + regexp.QuoteMeta(e) + `\s*(?:=|;)`)
		if m := re.FindStringSubmatch(body); m != nil && !headerWords[m[1]] && m[1] != "return" && m[1] != "emit" {
			typ = strings.ReplaceAll(m[1], " ", "")
		}
	}
	if typ == "" {
		for _, x := range append([]*unit{u}, s.bases(u)...) {
			if t, ok := x.vars[e]; ok {
				typ = t
				break
			}
		}
	}
	for ; indexed > 0 && typ != ""; indexed-- {
		typ = elemType(typ)
	}
	return typ
}

// elemType returns the element type of an array or mapping type.
func elemType(t string) string {
	if strings.HasPrefix(t, "mapping") {
		if i := strings.Index(t, "=>"); i >= 0 {
			v := strings.TrimSpace(t[i+2:])
			v = strings.TrimSuffix(v, ")")
			return strings.TrimSpace(v)
		}
		return ""
	}
	if i := strings.LastIndex(t, "["); i >= 0 {
		return t[:i]
	}
	return ""
}

var (
	reEncSel  = regexp.MustCompile(`abi\s*\.\s*(encodeWithSelector|encodeWithSignature|encodeCall)\s*\(`)
	reSelExpr = regexp.MustCompile(`^([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\.\s*selector$`)
	reKeccak  = regexp.MustCompile(`keccak256\s*\(\s*(?:bytes\s*\(\s*)?"([^"]+)"`)
	reFnSig   = regexp.MustCompile(`^([A-Za-z_]\w*)\(`)
	reTupleOK = regexp.MustCompile(`\(\s*bool\s+([A-Za-z_]\w*)\s*(?:,\s*bytes\s+memory\s+([A-Za-z_]\w*))?\s*(?:,\s*)?\)\s*=\s*$`)
)

// lowLevel recognises `target.staticcall(abi.encodeWithSelector(...))` and
// the encodeWithSignature / encodeCall forms whose function is a verify
// function.
func (s *scanner) lowLevel(u *unit, f sigFn, body, code, target, kind string, at, paren, pclose int) (VerifyCall, bool) {
	inner := body[paren+1 : pclose]
	icode := code[paren+1 : pclose]
	em := reEncSel.FindStringSubmatchIndex(icode)
	if em == nil {
		return VerifyCall{}, false
	}
	eopen := em[1] - 1
	eclose := matchClose(icode, eopen)
	if eclose < 0 {
		return VerifyCall{}, false
	}
	enc := icode[em[2]:em[3]]
	eargs := splitArgs(inner[eopen+1 : eclose])
	if len(eargs) == 0 {
		return VerifyCall{}, false
	}
	ll := &LowLevel{Kind: kind, Encoding: enc, SelectorExpr: squash(eargs[0])}
	vc := VerifyCall{Via: kind, LowLevel: ll}
	callee := ""
	var args []string
	switch enc {
	case "encodeWithSignature":
		sig := strings.Trim(strings.TrimSpace(eargs[0]), `"`)
		ll.Signature = strings.ReplaceAll(sig, " ", "")
		args = eargs[1:]
	case "encodeWithSelector":
		args = eargs[1:]
		if m := reSelExpr.FindStringSubmatch(ll.SelectorExpr); m != nil {
			callee = m[2]
			if x, ok := s.byName[m[1]]; ok {
				vc.ReceiverType = m[1]
				s.markUsed(m[1])
				vc.Target = s.findFnChain(x, m[2], len(args))
			}
		} else if m := reKeccak.FindStringSubmatch(ll.SelectorExpr); m != nil {
			ll.Signature = strings.ReplaceAll(m[1], " ", "")
		}
	case "encodeCall":
		if len(eargs) > 1 {
			t := strings.TrimSpace(eargs[1])
			if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
				args = splitArgs(t[1 : len(t)-1])
			} else {
				args = []string{t}
			}
		}
		parts := strings.Split(strings.ReplaceAll(ll.SelectorExpr, " ", ""), ".")
		if len(parts) == 2 {
			callee = parts[1]
			if x, ok := s.byName[parts[0]]; ok {
				vc.ReceiverType = parts[0]
				s.markUsed(parts[0])
				vc.Target = s.findFnChain(x, parts[1], len(args))
			}
		}
	}
	if ll.Signature != "" {
		if m := reFnSig.FindStringSubmatch(ll.Signature); m != nil {
			callee = m[1]
		}
		ll.Selector = keccak.Selector(ll.Signature)
	} else if vc.Target != nil && vc.Target.Signature != "" {
		ll.Signature, ll.Selector = vc.Target.Signature, vc.Target.Selector
	}
	if !reVerifyNm.MatchString(callee) {
		return VerifyCall{}, false
	}
	vc.Callee = callee
	vc.Args = args
	if len(args) > 0 {
		vc.InputArg = args[len(args)-1]
	}
	recv := squash(target)
	if m := reCast.FindStringSubmatch(recv); m != nil && (m[1] == "address" || m[1] == "payable") {
		recv = squash(m[2])
	}
	vc.Receiver = recv
	if vc.ReceiverType == "" {
		if t := s.varType(u, f, body, recv); t != "" {
			vc.ReceiverType = t
		}
	}
	// (bool ok, bytes memory ret) = target.staticcall(...)
	stStart := strings.LastIndexAny(body[:at], ";{}") + 1
	if m := reTupleOK.FindStringSubmatch(body[stStart:at]); m != nil {
		ll.SuccessVar, ll.ReturnVar = m[1], m[2]
	}
	vc.Statement = squash(statementAround(body, at, pclose))
	rest := code[pclose:]
	if ll.SuccessVar != "" {
		ok := regexp.QuoteMeta(ll.SuccessVar)
		ll.SuccessChecked = regexp.MustCompile(`(require|assert)\s*\(\s*` + ok + `\b|if\s*\(\s*!\s*` + ok + `\b|\b` + ok + `\s*&&|&&\s*` + ok + `\b|if\s*\(\s*` + ok + `\s*==\s*false`).MatchString(rest)
	} else {
		// require(target.staticcall(...)) is not valid Solidity; a success
		// flag that is never bound is never checked
		ll.SuccessChecked = false
	}
	if ll.ReturnVar != "" {
		ll.DecodesBool = regexp.MustCompile(`abi\s*\.\s*decode\s*\(\s*` + regexp.QuoteMeta(ll.ReturnVar) + `\s*,\s*\(\s*bool\s*\)`).MatchString(rest)
	}
	vc.ResultUsed = ll.SuccessChecked
	return vc, true
}

// resolveCalls maps every call site to the verifiers it can reach and to
// the contracts that inherit the calling one.
func (s *scanner) resolveCalls() {
	type vinfo struct {
		v Verifier
		u *unit
	}
	var vs []vinfo
	for _, v := range s.res.Verifiers {
		if u, ok := s.byName[v.Contract]; ok {
			vs = append(vs, vinfo{v, u})
		}
	}
	for i := range s.res.VerifyCalls {
		vc := &s.res.VerifyCalls[i]
		if u, ok := s.byName[vc.Contract]; ok && (u.kind == "abstract" || len(s.derived(u)) > 0) {
			vc.InheritedBy = s.derived(u)
		}
		add := func(x vinfo, match string) {
			for _, r := range vc.Verifiers {
				if r.Contract == x.v.Contract {
					return
				}
			}
			vc.Verifiers = append(vc.Verifiers, VerifierRef{Contract: x.v.Contract, File: x.v.File, Line: x.v.Line, Match: match})
		}
		sig := ""
		if vc.Target != nil {
			sig = vc.Target.Signature
		}
		if vc.LowLevel != nil && vc.LowLevel.Signature != "" {
			sig = vc.LowLevel.Signature
		}
		for _, x := range vs {
			switch {
			case vc.Via == "inherited" && vc.ReceiverType == x.v.Contract:
				add(x, "inherited-call")
			case vc.ReceiverType == x.v.Contract:
				add(x, "direct")
			}
		}
		for _, x := range vs {
			if vc.ReceiverType != "" {
				for _, b := range s.bases(x.u) {
					if b.name == vc.ReceiverType {
						add(x, "inherits")
					}
				}
			}
		}
		if vc.Via == "internal" || vc.Via == "inherited" || vc.Via == "library" || vc.Via == "using" {
			continue
		}
		for _, x := range vs {
			for _, fn := range x.u.info.Functions {
				if fn.Name == vc.Callee && sig != "" && fn.Signature == sig {
					add(x, "selector")
				}
			}
		}
		if len(vc.Verifiers) > 0 {
			continue
		}
		for _, x := range vs {
			for _, fn := range x.u.info.Functions {
				if fn.Name == vc.Callee {
					add(x, "name-only")
				}
			}
		}
	}
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
	sort.SliceStable(r.EntryPoints, func(i, j int) bool {
		return less(r.EntryPoints[i].File, r.EntryPoints[i].Line, r.EntryPoints[j].File, r.EntryPoints[j].Line)
	})
	sort.SliceStable(r.Contracts, func(i, j int) bool {
		return less(r.Contracts[i].File, r.Contracts[i].Line, r.Contracts[j].File, r.Contracts[j].Line)
	})
	sort.Strings(r.Notes)
}

func less(fa string, la int, fb string, lb int) bool {
	if fa != fb {
		return fa < fb
	}
	return la < lb
}

// NonGnarkVerifiers returns the verifiers not generated by gnark (custom,
// snarkjs, Halo2, ...): the inventory routes the custom-verifier slice on
// them.
func (r *Result) NonGnarkVerifiers() []Verifier {
	var out []Verifier
	if r == nil {
		return out
	}
	for _, v := range r.Verifiers {
		if v.Generator != GenGnark {
			out = append(out, v)
		}
	}
	return out
}

// ContractByName returns the first contract with that name.
func (r *Result) ContractByName(name string) (Contract, bool) {
	for _, c := range r.Contracts {
		if c.Name == name {
			return c, true
		}
	}
	return Contract{}, false
}

func appendUniqStr(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// ScanRepo scans the .sol files under root selected by scope (repo-relative
// files or directories; empty selects all), skipping Foundry dependency trees
// (lib/ next to a foundry.toml) and test and script files. Imports resolve
// with the repository's remappings, and imported files outside the scan are
// read as peripheral contracts.
func ScanRepo(root string, scope []string) (*Result, error) {
	tomls, err := fsutil.Walk(root, func(rel string) bool { return pathBase(rel) == "foundry.toml" })
	if err != nil {
		return nil, err
	}
	var libs, tomlRels []string
	for _, t := range tomls {
		tomlRels = append(tomlRels, t.Rel)
		d := pathDir(t.Rel)
		if d == "." {
			libs = append(libs, "lib/")
		} else {
			libs = append(libs, d+"/lib/")
		}
	}
	sols, err := fsutil.Walk(root, func(rel string) bool {
		if !strings.HasSuffix(rel, ".sol") || !fsutil.InScope(rel, scope) {
			return false
		}
		for _, l := range libs {
			if strings.HasPrefix(rel, l) {
				return false
			}
		}
		return !strings.HasSuffix(rel, ".t.sol") && !strings.HasSuffix(rel, ".s.sol")
	})
	if err != nil {
		return nil, err
	}
	return Scan(sols, Options{Root: root, Remappings: LoadRemappings(root, tomlRels)})
}

func pathBase(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

func pathDir(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}
