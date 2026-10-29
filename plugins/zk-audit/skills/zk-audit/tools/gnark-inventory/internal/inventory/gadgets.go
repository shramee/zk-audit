package inventory

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
)

// Gadget is one exported function or method that builds constraints: it
// takes a frontend.API or an *emulated.Field, or it is a method of an
// exported type that holds one. Library mode audits each gadget against
// its doc comment (lens L1).
type Gadget struct {
	ID         string `json:"id"`
	Name       string `json:"name"` // package.Func or package.Type.Method
	Package    string `json:"package"`
	ImportPath string `json:"import_path,omitempty"`
	Pos        Pos    `json:"pos"`
	Signature  string `json:"signature"`
	Doc        string `json:"doc"`
	// Receiver is the receiver type of a method gadget.
	Receiver string          `json:"receiver,omitempty"`
	Params   []*GadgetParam  `json:"params"`
	Results  []*GadgetResult `json:"results"`
	Promises []DocClaim      `json:"doc_promises"`
	Preconds []DocClaim      `json:"doc_preconditions"`
	// Constraints are the constraining calls in the body and in the
	// same-package functions it calls (Name@file:line).
	Constraints []string `json:"constraint_calls"`
	// Followed lists the same-package callees whose bodies were read.
	Followed []string `json:"followed_calls"`
	// HintIDs are the inventory hint sites in the body and followed callees.
	HintIDs []string `json:"hint_ids"`
	// Checks are deterministic doc-versus-constraint notes for L1: a
	// promised property with no constraint of that kind seen, an input that
	// reaches no constraint and that no precondition names. They are
	// facts to check, never verdicts.
	Checks []DocCheck `json:"doc_checks"`
	InTest bool       `json:"in_test_file"`
}

// GadgetParam is one parameter and where it flows.
type GadgetParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Kind: api, field, variable, variables, element, int, other.
	Kind string `json:"kind"`
	// Flow: constrained (reaches a constraining call, possibly through a
	// same-package callee), hint-input (only feeds hints), escapes (only
	// returned, stored or passed on), arithmetic-only (used, no constraint),
	// unused, or compile-time (an int or bool parameter). "–" for the api
	// and field parameters.
	Flow      string   `json:"flow"`
	ReachedBy []string `json:"reached_by,omitempty"`
}

// GadgetResult is one result and where its value comes from.
type GadgetResult struct {
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	// Source: hint (a hint output returned; see Hints), input (derived
	// from parameters), computed (no hint or parameter origin found) or
	// none (the type carries no value, e.g. error).
	Source string `json:"source"`
	// Hints names each hint output returned and whether it reaches a
	// constraint in the gadget: "H3[1] reached" / "H3[1] escapes".
	Hints []string `json:"hints,omitempty"`
}

// DocClaim is one sentence of a doc comment classified by property.
type DocClaim struct {
	Kinds []string `json:"kinds"`
	Text  string   `json:"text"`
}

// DocCheck is one deterministic note for the doc-contract lens.
type DocCheck struct {
	Kind string `json:"kind"`
	Note string `json:"note"`
}

// promise and precondition vocabulary
var (
	rePrecond  = regexp.MustCompile(`(?i)\b(caller must|caller should|callers must|must be|must not|must ensure|should be|assumes?|assuming|expects?|requires?|precondition|responsibility of the caller|caller's responsibility|undefined (if|when|for)|only (valid|defined|sound) (if|when|for)|not checked|does not check|doesn't check|unchecked|not constrained|is not range[- ]checked)\b`)
	claimKinds = []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"boolean", regexp.MustCompile(`(?i)(\bboolean|\b0 or 1\b|\{0, ?1\}|\bbits of\b|\bbit decomposition|\bbinary decomposition)`)},
		{"range", regexp.MustCompile(`(?i)(\brange|< ?2\^|<= ?2\^|less than|at most|at least|bounded|\bbits?\b|\bwidth|\bbelow\b|\babove\b|<|<=|>=|\bfits?\b)`)},
		{"canonical", regexp.MustCompile(`(?i)\b(canonical|strictly reduced|reduced modulo|less than the modulus|below (the modulus|p)\b|< ?p\b|unique representation)`)},
		{"on-curve", regexp.MustCompile(`(?i)(on the curve|on-curve|\bon curve|subgroup|on the twist|\btwist\b|torsion)`)},
		{"nonzero", regexp.MustCompile(`(?i)(non-?zero|not zero|!= ?0|\binvertible)`)},
		{"relation", regexp.MustCompile(`(?i)(\brecompose|\bequals?\b|\bsatisf|\b[a-z]\w* ?= ?[a-z0-9]|\bsuch that\b|\bwith [a-z]\w* ?=)`)},
	}
	// the constraining calls that can establish each promised kind
	kindSinks = map[string]map[string]bool{
		"boolean":   setOf("AssertIsBoolean", "ToBinary", "AssertIsCrumb", "ToBase"),
		"range":     setOf("ToBinary", "ToBase", "AssertIsLessOrEqual", "AssertIsInRange", "Check", "AssertIsLess", "AssertIsLessEq", "MustBeLessOrEqCst", "ReduceStrict", "AssertIsBoolean", "AssertIsCrumb"),
		"canonical": setOf("ReduceStrict", "AssertIsInRange", "AssertIsLess", "AssertIsLessEq", "AssertIsLessOrEqual", "ToBinary", "MustBeLessOrEqCst"),
		"on-curve":  setOf("AssertIsOnCurve", "AssertIsOnG1", "AssertIsOnG2", "AssertIsOnTwist", "AssertIsOnCurveG1"),
		"nonzero":   setOf("AssertIsDifferent", "Inverse", "Div", "AssertIsNonZero"),
	}
	reSentence = regexp.MustCompile(`[.;]\s+`)
)

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// classifyDoc splits a doc comment into promise and precondition sentences.
func classifyDoc(doc string) (promises, preconds []DocClaim) {
	text := strings.Join(strings.Fields(doc), " ")
	for _, s := range reSentence.Split(text, -1) {
		s = strings.TrimSpace(strings.TrimSuffix(s, "."))
		if s == "" || strings.HasPrefix(s, "Deprecated:") {
			continue
		}
		var kinds []string
		for _, k := range claimKinds {
			if k.re.MatchString(s) {
				kinds = append(kinds, k.kind)
			}
		}
		if rePrecond.MatchString(s) {
			preconds = append(preconds, DocClaim{Kinds: orOther(kinds), Text: s})
			continue
		}
		if len(kinds) > 0 {
			promises = append(promises, DocClaim{Kinds: kinds, Text: s})
		}
	}
	return
}

func orOther(k []string) []string {
	if len(k) == 0 {
		return []string{"other"}
	}
	return k
}

// gadgetPass analyses the exported gadgets of a program.
type gadgetPass struct {
	prog *load.Program
	inv  *Inventory
	// funcs maps "dir|name" and "dir|Recv.name" to declarations
	funcs map[string]funcRef
	// memo of parameter flows: "dir|name|index"
	memo map[string]*paramFlow
}

type funcRef struct {
	f  *load.File
	fd *ast.FuncDecl
}

type paramFlow struct {
	constrained bool
	reachedBy   []string
	escapes     []string
	hintInput   bool
	sinks       []string // every constraining call reached in the callee, any origin
}

func funcKey(f *load.File, fd *ast.FuncDecl) string {
	dir := path.Dir(f.Rel)
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return dir + "|" + recvTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return dir + "|" + fd.Name.Name
}

// findGadgets lists every exported gadget in scope. circuitTypes holds
// "dir|Type" for each circuit (their methods are not gadgets).
func findGadgets(prog *load.Program, inv *Inventory, inScope func(string) bool, circuitTypes map[string]bool) []*Gadget {
	g := &gadgetPass{prog: prog, inv: inv, funcs: map[string]funcRef{}, memo: map[string]*paramFlow{}}
	holders := map[string]bool{} // dir|Type of exported types holding an API or a Field
	for _, f := range prog.Files {
		if f.IsTest {
			continue
		}
		for _, d := range f.AST.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if x.Body != nil {
					g.funcs[funcKey(f, x)] = funcRef{f, x}
				}
			case *ast.GenDecl:
				if x.Tok != token.TYPE {
					continue
				}
				for _, sp := range x.Specs {
					ts := sp.(*ast.TypeSpec)
					st, ok := ts.Type.(*ast.StructType)
					if !ok || !ts.Name.IsExported() {
						continue
					}
					for _, fl := range st.Fields.List {
						if isAPIType(f, fl.Type) || isFieldType(f, fl.Type) {
							holders[path.Dir(f.Rel)+"|"+ts.Name.Name] = true
						}
					}
				}
			}
		}
	}
	var out []*Gadget
	for _, f := range prog.Files {
		if f.IsTest || f.AST.Name.Name == "main" || !importsGnark(f) || !inScope(f.Rel) {
			continue
		}
		dir := path.Dir(f.Rel)
		for _, d := range f.AST.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !fd.Name.IsExported() || fd.Name.Name == "Define" {
				continue
			}
			recv := ""
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				recv = recvTypeName(fd.Recv.List[0].Type)
				if !ast.IsExported(recv) || circuitTypes[dir+"|"+recv] {
					continue
				}
			}
			if !takesGadgetParam(f, fd.Type) && !(recv != "" && holders[dir+"|"+recv]) {
				continue
			}
			out = append(out, g.analyze(f, fd, recv))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pos.File != out[j].Pos.File {
			return out[i].Pos.File < out[j].Pos.File
		}
		return out[i].Pos.Line < out[j].Pos.Line
	})
	for i, x := range out {
		x.ID = fmt.Sprintf("G%d", i+1)
	}
	return out
}

func takesGadgetParam(f *load.File, ft *ast.FuncType) bool {
	if ft.Params == nil {
		return false
	}
	for _, p := range ft.Params.List {
		if isAPIType(f, p.Type) || isFieldType(f, p.Type) {
			return true
		}
	}
	return false
}

// isFieldType reports whether e is (*)emulated.Field[T].
func isFieldType(f *load.File, e ast.Expr) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	switch x := e.(type) {
	case *ast.IndexExpr:
		e = x.X
	case *ast.IndexListExpr:
		e = x.X
	}
	return isPkgSel(f, e, pkgEmulated, "Field")
}

func paramKind(f *load.File, e ast.Expr) string {
	switch {
	case isAPIType(f, e):
		return "api"
	case isFieldType(f, e):
		return "field"
	case isPkgSel(f, e, pkgFrontend, "Variable"):
		return "variable"
	}
	switch x := e.(type) {
	case *ast.ArrayType:
		if isPkgSel(f, x.Elt, pkgFrontend, "Variable") {
			return "variables"
		}
	case *ast.Ident:
		switch x.Name {
		case "int", "uint", "int64", "uint64", "uint8", "uint16", "uint32", "int32", "bool":
			return "int"
		}
	case *ast.StarExpr:
		if ix, ok := x.X.(*ast.IndexExpr); ok && isPkgSel(f, ix.X, pkgEmulated, "Element") {
			return "element"
		}
	case *ast.IndexExpr:
		if isPkgSel(f, x.X, pkgEmulated, "Element") {
			return "element"
		}
	}
	return "other"
}

// analyze builds one gadget record.
func (g *gadgetPass) analyze(f *load.File, fd *ast.FuncDecl, recv string) *Gadget {
	file, line := g.prog.Pos(f, fd)
	name := f.AST.Name.Name + "." + fd.Name.Name
	if recv != "" {
		name = f.AST.Name.Name + "." + recv + "." + fd.Name.Name
	}
	doc := ""
	if fd.Doc != nil {
		doc = strings.TrimSpace(fd.Doc.Text())
	}
	sig := exprStringFull(g.prog, &ast.FuncDecl{Recv: fd.Recv, Name: fd.Name, Type: fd.Type})
	gd := &Gadget{Name: name, Package: path.Dir(f.Rel), ImportPath: f.Pkg.PkgPath, Pos: Pos{File: file, Line: line}, Signature: sig, Doc: doc, Receiver: recv,
		Params: []*GadgetParam{}, Results: []*GadgetResult{}, Promises: []DocClaim{}, Preconds: []DocClaim{}, Constraints: []string{}, Followed: []string{}, HintIDs: []string{}, Checks: []DocCheck{}, InTest: f.IsTest}
	gd.Promises, gd.Preconds = classifyDoc(doc)
	if gd.Promises == nil {
		gd.Promises = []DocClaim{}
	}
	if gd.Preconds == nil {
		gd.Preconds = []DocClaim{}
	}

	// one analyzer: hint sites first, then one root per parameter
	scope := newFuncScope(f, fd)
	a := newHintAnalyzer(g.prog, f, scope)
	tmp := 0
	a.findSites(fd.Body, func() string { tmp++; return fmt.Sprintf("site%d", tmp) })
	nHints := len(a.states)
	var params []*ast.Ident
	if fd.Type.Params != nil {
		for _, p := range fd.Type.Params.List {
			kind := paramKind(f, p.Type)
			for _, n := range p.Names {
				gp := &GadgetParam{Name: n.Name, Type: exprString(g.prog.Fset, p.Type), Kind: kind}
				gd.Params = append(gd.Params, gp)
				params = append(params, n)
				if n.Name == "_" || kind == "api" || kind == "field" {
					continue
				}
				a.roots[a.key(n)] = len(a.states)
				a.states = append(a.states, &hintState{site: &HintSite{ID: "param:" + n.Name}, nb: -1, reached: map[string][]string{}, escapes: map[string][]string{}, observed: map[string]bool{}})
			}
		}
	}
	// the receiver's fields hold the API: c.api.X(...) is in scope
	followed := map[string]bool{}
	var sinks []string
	a.onCall = func(call *ast.CallExpr, c callee, label string) bool {
		ref, ok := g.sameFunc(f, c, recv, scope.RecvName)
		if !ok {
			return false
		}
		k := funcKey(ref.f, ref.fd)
		followed[k] = true
		handled := false
		for i, arg := range call.Args {
			os := a.originsOf(arg)
			if len(os) == 0 {
				continue
			}
			pf := g.flowOfParam(ref, i, 0, followed)
			if pf == nil {
				continue
			}
			handled = true
			via := "via " + ref.fd.Name.Name + "@" + a.pos(call)
			if pf.constrained {
				a.recordReached(os, via)
			} else if len(pf.escapes) > 0 {
				a.recordEscape(os, "call:"+label)
			}
		}
		return handled
	}
	a.propagate(fd.Body)
	a.sinks(fd.Body)
	// hint inputs
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !hintCallNames[calleeOf(f, call).Name] {
			return true
		}
		for _, arg := range call.Args[min(2, len(call.Args)):] {
			for o := range a.originsOf(arg) {
				if o.site >= nHints {
					a.states[o.site].observed["hint-input"] = true
				}
			}
		}
		return true
	})
	// constraining calls in the body
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if c := calleeOf(f, call); sinkNames[c.Name] {
				sinks = append(sinks, c.Name+"@"+a.pos(call))
			}
		}
		return true
	})
	// parameters
	pi := 0
	for _, gp := range gd.Params {
		if gp.Name == "_" || gp.Kind == "api" || gp.Kind == "field" {
			gp.Flow = "–"
			continue
		}
		st := a.states[nHints+pi]
		if gp.Kind == "int" {
			pi++
			gp.Flow = "compile-time"
			continue
		}
		pi++
		var reached, esc []string
		for _, v := range st.reached {
			reached = append(reached, v...)
		}
		for _, v := range st.escapes {
			esc = append(esc, v...)
		}
		used := usesIdent(fd.Body, gp.Name)
		switch {
		case len(reached) > 0:
			gp.Flow = "constrained"
			sort.Strings(reached)
			gp.ReachedBy = uniq(reached)
		case st.observed["hint-input"] && len(esc) == 0:
			gp.Flow = "hint-input"
		case len(esc) > 0:
			gp.Flow = "escapes"
		case used:
			gp.Flow = "arithmetic-only"
		default:
			gp.Flow = "unused"
		}
	}
	// hint sites: link to the inventory's ids by position, finish them
	for i := 0; i < nHints; i++ {
		finishSite(a.states[i])
		for _, h := range g.inv.Hints {
			if h.Pos == a.states[i].site.Pos {
				gd.HintIDs = appendUniq(gd.HintIDs, h.ID)
				a.states[i].site.ID = h.ID
			}
		}
	}
	// results
	g.results(gd, fd, a, nHints)
	// followed callees: their constraints and hints
	var keys []string
	for k := range followed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		gd.Followed = append(gd.Followed, k[strings.IndexByte(k, '|')+1:])
		ref := g.funcs[k]
		ast.Inspect(ref.fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if c := calleeOf(ref.f, call); sinkNames[c.Name] {
					_, line := g.prog.Pos(ref.f, call)
					sinks = append(sinks, fmt.Sprintf("%s@%s:%d", c.Name, ref.f.Rel, line))
				}
			}
			return true
		})
		for _, h := range g.inv.Hints {
			if h.Pos.File == ref.f.Rel && h.Function == newFuncScope(ref.f, ref.fd).Name {
				gd.HintIDs = appendUniq(gd.HintIDs, h.ID)
			}
		}
	}
	gd.Constraints = uniq(sinks)
	if gd.Constraints == nil {
		gd.Constraints = []string{}
	}
	g.checks(gd)
	return gd
}

// sameFunc resolves a call to a function of the gadget's own package, or
// to a method of the same receiver type called through the receiver.
func (g *gadgetPass) sameFunc(f *load.File, c callee, recv, recvName string) (funcRef, bool) {
	dir := path.Dir(f.Rel)
	if c.Pkg != "" {
		return funcRef{}, false
	}
	if c.Recv == nil {
		ref, ok := g.funcs[dir+"|"+c.Name]
		return ref, ok
	}
	if id, ok := c.Recv.(*ast.Ident); ok && recv != "" && recvName != "" && id.Name == recvName {
		ref, ok := g.funcs[dir+"|"+recv+"."+c.Name]
		return ref, ok
	}
	return funcRef{}, false
}

// flowOfParam analyses where parameter index i of a same-package function
// flows (depth-limited, memoised).
func (g *gadgetPass) flowOfParam(ref funcRef, i, depth int, followed map[string]bool) *paramFlow {
	key := fmt.Sprintf("%s|%d", funcKey(ref.f, ref.fd), i)
	if pf, ok := g.memo[key]; ok {
		return pf
	}
	if depth > 4 {
		return nil
	}
	g.memo[key] = &paramFlow{} // break recursion
	var target *ast.Ident
	n := 0
	if ref.fd.Type.Params != nil {
		for _, p := range ref.fd.Type.Params.List {
			for _, nm := range p.Names {
				if n == i {
					target = nm
				}
				n++
			}
			if len(p.Names) == 0 {
				n++
			}
		}
	}
	if target == nil || target.Name == "_" {
		return nil
	}
	sc := newFuncScope(ref.f, ref.fd)
	a := newHintAnalyzer(g.prog, ref.f, sc)
	a.roots[a.key(target)] = 0
	st := &hintState{site: &HintSite{ID: "param"}, nb: -1, reached: map[string][]string{}, escapes: map[string][]string{}, observed: map[string]bool{}}
	a.states = append(a.states, st)
	recv := ""
	if ref.fd.Recv != nil && len(ref.fd.Recv.List) > 0 {
		recv = recvTypeName(ref.fd.Recv.List[0].Type)
	}
	a.onCall = func(call *ast.CallExpr, c callee, label string) bool {
		r2, ok := g.sameFunc(ref.f, c, recv, sc.RecvName)
		if !ok {
			return false
		}
		followed[funcKey(r2.f, r2.fd)] = true
		handled := false
		for j, arg := range call.Args {
			os := a.originsOf(arg)
			if len(os) == 0 {
				continue
			}
			pf := g.flowOfParam(r2, j, depth+1, followed)
			if pf == nil {
				continue
			}
			handled = true
			if pf.constrained {
				a.recordReached(os, "via "+r2.fd.Name.Name+"@"+a.pos(call))
			} else if len(pf.escapes) > 0 {
				a.recordEscape(os, "call:"+label)
			}
		}
		return handled
	}
	a.propagate(ref.fd.Body)
	a.sinks(ref.fd.Body)
	pf := &paramFlow{}
	for _, v := range st.reached {
		pf.reachedBy = append(pf.reachedBy, v...)
	}
	for _, v := range st.escapes {
		pf.escapes = append(pf.escapes, v...)
	}
	pf.constrained = len(pf.reachedBy) > 0
	g.memo[key] = pf
	return pf
}

// results classifies each result of the gadget from its return statements.
func (g *gadgetPass) results(gd *Gadget, fd *ast.FuncDecl, a *hintAnalyzer, nHints int) {
	if fd.Type.Results == nil {
		return
	}
	var named []*ast.Ident
	idx := 0
	for _, r := range fd.Type.Results.List {
		names := r.Names
		if len(names) == 0 {
			names = []*ast.Ident{nil}
		}
		for _, n := range names {
			gr := &GadgetResult{Index: idx, Type: exprString(g.prog.Fset, r.Type)}
			if n != nil {
				gr.Name = n.Name
			}
			named = append(named, n)
			gd.Results = append(gd.Results, gr)
			idx++
		}
	}
	hintOut := map[int]map[string]bool{}
	fromInput := map[int]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			exprs := x.Results
			if len(exprs) == 0 { // bare return of named results
				for _, nm := range named {
					if nm != nil {
						exprs = append(exprs, nm)
					}
				}
			}
			if len(exprs) != len(gd.Results) {
				return true
			}
			for i, e := range exprs {
				for o := range a.originsOf(e) {
					if o.site < nHints {
						if hintOut[i] == nil {
							hintOut[i] = map[string]bool{}
						}
						st := a.states[o.site]
						status := "escapes"
						for _, out := range st.site.Outputs {
							if out.Index == o.index || o.index == "*" {
								if out.Status == "reached" {
									status = "reached"
								}
							}
						}
						hintOut[i][fmt.Sprintf("%s[%s] %s", st.site.ID, o.index, status)] = true
					} else {
						fromInput[i] = true
					}
				}
			}
		}
		return true
	})
	for i, gr := range gd.Results {
		switch {
		case gr.Type == "error":
			gr.Source = "none"
		case len(hintOut[i]) > 0:
			gr.Source = "hint"
			for h := range hintOut[i] {
				gr.Hints = append(gr.Hints, h)
			}
			sort.Strings(gr.Hints)
		case fromInput[i]:
			gr.Source = "input"
		default:
			gr.Source = "computed"
		}
	}
}

// checks adds the deterministic doc-versus-constraint notes.
func (g *gadgetPass) checks(gd *Gadget) {
	seen := map[string]bool{}
	for _, c := range gd.Constraints {
		name := c
		if i := strings.IndexByte(c, '@'); i > 0 {
			name = c[:i]
		}
		seen[name] = true
	}
	flagged := map[string]bool{}
	for _, p := range gd.Promises {
		for _, k := range p.Kinds {
			sinks, ok := kindSinks[k]
			if !ok || flagged[k] {
				continue
			}
			found := false
			for s := range sinks {
				if seen[s] {
					found = true
				}
			}
			if !found {
				flagged[k] = true
				gd.Checks = append(gd.Checks, DocCheck{Kind: "promise-" + k,
					Note: fmt.Sprintf("the doc promises %s (%q) but no %s constraint (%s) appears in the gadget or its same-package callees", k, p.Text, k, strings.Join(sortedKeys(sinks), ", "))})
			}
		}
	}
	for _, r := range gd.Results {
		for _, h := range r.Hints {
			if strings.HasSuffix(h, " escapes") {
				gd.Checks = append(gd.Checks, DocCheck{Kind: "result-from-hint",
					Note: fmt.Sprintf("result %d returns hint output %s with no constraint in the gadget: the doc must say what the caller has to constrain", r.Index, strings.TrimSuffix(h, " escapes"))})
			}
		}
	}
	precText := ""
	for _, p := range gd.Preconds {
		precText += " " + p.Text
	}
	for _, p := range gd.Params {
		if p.Kind == "int" {
			continue // compile-time parameter, not a witness value
		}
		switch p.Flow {
		case "arithmetic-only", "hint-input":
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(p.Name) + `\b`).MatchString(precText) {
				gd.Checks = append(gd.Checks, DocCheck{Kind: "input-precondition",
					Note: fmt.Sprintf("input %s (%s) reaches no constraint in the gadget (%s) and no documented precondition names it: is any value of it sound?", p.Name, p.Type, p.Flow)})
			}
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniq(xs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func usesIdent(body ast.Node, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// exprStringFull prints a node without the length cap of exprString.
func exprStringFull(prog *load.Program, n ast.Node) string {
	s := exprString(prog.Fset, n)
	if len(s) >= 160 && strings.HasSuffix(s, "...") {
		var b strings.Builder
		if fd, ok := n.(*ast.FuncDecl); ok {
			b.WriteString("func ")
			if fd.Recv != nil {
				b.WriteString("(" + exprString(prog.Fset, fd.Recv.List[0].Type) + ") ")
			}
			b.WriteString(fd.Name.Name + "(")
			var ps []string
			for _, p := range fd.Type.Params.List {
				t := exprString(prog.Fset, p.Type)
				var ns []string
				for _, nm := range p.Names {
					ns = append(ns, nm.Name)
				}
				ps = append(ps, strings.TrimSpace(strings.Join(ns, ", ")+" "+t))
			}
			b.WriteString(strings.Join(ps, ", ") + ")")
			return b.String()
		}
	}
	return s
}
