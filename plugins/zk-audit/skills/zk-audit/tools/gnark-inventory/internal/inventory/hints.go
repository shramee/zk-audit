package inventory

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
)

// hintCallNames are the methods that create hint outputs.
var hintCallNames = map[string]bool{
	"NewHint": true, "NewHintWithNativeInput": true, "NewHintWithNativeOutput": true, "NewHintGeneric": true,
}

// sinkNames are calls that put a constraint on their arguments. Reaching one
// is necessary, not sufficient, for a hint output to be bound.
var sinkNames = map[string]bool{
	"AssertIsEqual": true, "AssertIsDifferent": true, "AssertIsBoolean": true, "AssertIsCrumb": true,
	"AssertIsLessOrEqual": true, "AssertIsInRange": true, "ToBinary": true, "ToBase": true,
	"FromBinary": true, "FromBase": true, "Check": true, "ModAssertIsEqual": true,
	"AssertEvalIsZero": true, "MustBeLessOrEqCst": true, "AssertIsOnCurve": true, "AssertProof": true,
	"AssertIsLess": true, "AssertIsLessEq": true, "AssertIsOnG1": true, "AssertIsOnG2": true,
	"AssertIsOnTwist": true, "AssertIsZero": true, "AssertIsEqualMod": true, "Lookup": true,
	"AssertIsOnCurveG1": true, "AssertFinalExponentiationIsOne": true, "PairingCheck": true,
}

// propagatorNames are API calls whose result is derived from their inputs
// and which do not, by themselves, bind those inputs.
var propagatorNames = map[string]bool{
	"Add": true, "Sub": true, "Mul": true, "Neg": true, "Div": true, "DivUnchecked": true, "Inverse": true,
	"MulAcc": true, "Select": true, "Lookup2": true, "Xor": true, "Or": true, "And": true, "IsZero": true,
	"Cmp": true, "Mux": true, "Println": true, "Reduce": true, "ReduceStrict": true, "MulMod": true,
	"MulNoReduce": true, "Sum": true, "Exp": true, "ModMul": true, "ModAdd": true, "Eval": true,
	"append": true, "len": true, "make": true, "copy": true, "new": true, "big.NewInt": true,
}

type origin struct {
	site  int
	index string // constant index, or "*" for whole-slice use
}

type hintState struct {
	site     *HintSite
	nb       int // -1 when unknown
	reached  map[string][]string
	escapes  map[string][]string
	rootKey  string
	observed map[string]bool
}

type hintAnalyzer struct {
	prog   *load.Program
	f      *load.File
	scope  *funcScope
	states []*hintState
	// onCall, when set, may handle a call with tainted arguments (the
	// gadget pass follows same-package callees); it reports whether it did.
	onCall func(call *ast.CallExpr, c callee, label string) bool
	// taint maps a variable key to its origins
	taint map[string]map[origin]bool
	// roots maps a root slice variable key to its site index
	roots map[string]int
}

func (a *hintAnalyzer) key(id *ast.Ident) string {
	if a.f.Pkg.Info != nil {
		if obj := a.f.Pkg.Info.ObjectOf(id); obj != nil {
			return fmt.Sprintf("obj:%p", obj)
		}
	}
	return "name:" + id.Name
}

func (a *hintAnalyzer) pos(n ast.Node) string {
	p := a.prog.Fset.Position(n.Pos())
	return fmt.Sprintf("%s:%d", a.f.Rel, p.Line)
}

// originsOf returns every hint origin that flows into e.
func (a *hintAnalyzer) originsOf(e ast.Node) map[origin]bool {
	out := map[origin]bool{}
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.IndexExpr:
				if id, ok := x.X.(*ast.Ident); ok {
					if site, ok := a.roots[a.key(id)]; ok {
						if k, ok := intLit(x.Index); ok {
							out[origin{site, strconv.Itoa(k)}] = true
						} else {
							out[origin{site, "*"}] = true
							visit(x.Index)
						}
						return false
					}
				}
			case *ast.Ident:
				k := a.key(x)
				if site, ok := a.roots[k]; ok {
					out[origin{site, "*"}] = true
				}
				for o := range a.taint[k] {
					out[o] = true
				}
			case *ast.FuncLit:
				return false
			}
			return true
		})
	}
	visit(e)
	return out
}

func (a *hintAnalyzer) addTaint(id *ast.Ident, os map[origin]bool) bool {
	if id == nil || id.Name == "_" || len(os) == 0 {
		return false
	}
	k := a.key(id)
	if _, isRoot := a.roots[k]; isRoot {
		return false
	}
	m := a.taint[k]
	if m == nil {
		m = map[origin]bool{}
		a.taint[k] = m
	}
	changed := false
	for o := range os {
		if !m[o] {
			m[o] = true
			changed = true
		}
	}
	return changed
}

func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return nil
		}
	}
}

func appendUniq(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// analyzeHints finds hint call sites in one function and classifies the
// reachability of their outputs. It returns the sites found.
func analyzeHints(prog *load.Program, f *load.File, scope *funcScope, body *ast.BlockStmt, nextID func() string) []*HintSite {
	a := newHintAnalyzer(prog, f, scope)

	a.findSites(body, nextID)
	if len(a.states) == 0 {
		return nil
	}
	a.propagate(body)
	a.sinks(body)

	// 4. verdicts
	var out []*HintSite
	for _, st := range a.states {
		finishSite(st)
		out = append(out, st.site)
	}
	return out
}

func (a *hintAnalyzer) recordReached(os map[origin]bool, what string) {
	for o := range os {
		st := a.states[o.site]
		st.reached[o.index] = appendUniq(st.reached[o.index], what)
	}
}

func (a *hintAnalyzer) recordEscape(os map[origin]bool, what string) {
	for o := range os {
		st := a.states[o.site]
		st.escapes[o.index] = appendUniq(st.escapes[o.index], what)
	}
}

func finishSite(st *hintState) {
	var indices []string
	if st.nb >= 0 {
		for i := 0; i < st.nb; i++ {
			indices = append(indices, strconv.Itoa(i))
		}
	} else {
		seen := map[string]bool{}
		for k := range st.reached {
			seen[k] = true
		}
		for k := range st.escapes {
			seen[k] = true
		}
		delete(seen, "*")
		for k := range seen {
			indices = append(indices, k)
		}
		sort.Slice(indices, func(i, j int) bool { return numLess(indices[i], indices[j]) })
		indices = append(indices, "*")
	}
	r, u, e := 0, 0, 0
	for _, ix := range indices {
		o := &HintOutput{Index: ix}
		if ix == "*" {
			o.ReachedBy = st.reached["*"]
			o.Escapes = st.escapes["*"]
		} else {
			o.ReachedBy = append(append([]string{}, st.reached[ix]...), st.reached["*"]...)
			o.Escapes = append(append([]string{}, st.escapes[ix]...), st.escapes["*"]...)
		}
		switch {
		case len(o.ReachedBy) > 0:
			o.Status = "reached"
			r++
		case len(o.Escapes) > 0:
			o.Status = "escapes"
			e++
		case ix == "*" && len(indices) > 1:
			// count unknown and only explicit indices were used: any
			// further outputs are unused, which counts as unreached
			o.Status = "unknown"
			u++
		default:
			o.Status = "unreached"
			u++
		}
		st.site.Outputs = append(st.site.Outputs, o)
	}
	switch {
	case u == 0 && e == 0:
		st.site.Status = "reached"
	case u == 0:
		st.site.Status = "escapes"
	case r == 0 && e == 0:
		st.site.Status = "unreached"
	default:
		st.site.Status = "partially_unreached"
	}
}

func numLess(a, b string) bool {
	x, e1 := strconv.Atoi(a)
	y, e2 := strconv.Atoi(b)
	if e1 == nil && e2 == nil {
		return x < y
	}
	return a < b
}

// hintFuncs returns functions with the solver.Hint signature.
func hintFuncs(prog *load.Program, f *load.File) []*HintFunc {
	var out []*HintFunc
	for _, d := range f.AST.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || !isHintSig(prog.Fset, fd.Type) {
			continue
		}
		file, line := prog.Pos(f, fd)
		out = append(out, &HintFunc{Name: fd.Name.Name, Pos: Pos{File: file, Line: line}})
	}
	return out
}

func isHintSig(fset *token.FileSet, ft *ast.FuncType) bool {
	if ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	if id, ok := ft.Results.List[0].Type.(*ast.Ident); !ok || id.Name != "error" {
		return false
	}
	var ts []string
	for _, p := range ft.Params.List {
		n := len(p.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			ts = append(ts, strings.ReplaceAll(exprString(fset, p.Type), " ", ""))
		}
	}
	return len(ts) == 3 && ts[0] == "*big.Int" && ts[1] == "[]*big.Int" && ts[2] == "[]*big.Int"
}

// registeredHints returns names passed to solver.RegisterHint / WithHints.
func registeredHints(prog *load.Program, f *load.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		c := calleeOf(f, call)
		if c.Name != "RegisterHint" && c.Name != "WithHints" && c.Name != "OverrideHint" {
			return true
		}
		for _, a := range call.Args {
			switch x := a.(type) {
			case *ast.Ident:
				out[x.Name] = true
			case *ast.SelectorExpr:
				out[x.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

// propagate spreads taint through assignments, declarations and range
// loops to a fixed point.
func (a *hintAnalyzer) propagate(body ast.Node) {
	for iter := 0; iter < 10; iter++ {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				var all map[origin]bool
				if len(x.Rhs) == 1 {
					all = a.originsOf(x.Rhs[0])
				}
				for i, lhs := range x.Lhs {
					os := all
					if len(x.Rhs) == len(x.Lhs) {
						os = a.originsOf(x.Rhs[i])
					}
					if len(os) == 0 {
						continue
					}
					switch l := lhs.(type) {
					case *ast.Ident:
						if a.addTaint(l, os) {
							changed = true
						}
					case *ast.SelectorExpr:
						a.recordEscape(os, "field:"+exprString(a.prog.Fset, l)+"@"+a.pos(l))
					default:
						if id := rootIdent(lhs); id != nil && a.addTaint(id, os) {
							changed = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					var os map[origin]bool
					if len(x.Values) == len(x.Names) {
						os = a.originsOf(x.Values[i])
					} else if len(x.Values) == 1 {
						os = a.originsOf(x.Values[0])
					}
					if a.addTaint(nm, os) {
						changed = true
					}
				}
			case *ast.RangeStmt:
				os := a.originsOf(x.X)
				if k, ok := x.Key.(*ast.Ident); ok && x.Value == nil {
					_ = k // index over a tainted slice carries no value
				}
				if v, ok := x.Value.(*ast.Ident); ok && a.addTaint(v, os) {
					changed = true
				}
			}
			return true
		})
		if !changed {
			break
		}
	}

}

// sinks records, for every tainted value, the constraining calls it
// reaches and the ways it leaves the function (return, struct field,
// composite literal, call to a non-API function).
func (a *hintAnalyzer) sinks(body ast.Node) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			c := calleeOf(a.f, x)
			if hintCallNames[c.Name] {
				// hint inputs are not sinks; nested hint chains are tracked separately
				return true
			}
			os := map[origin]bool{}
			for _, arg := range x.Args {
				for o := range a.originsOf(arg) {
					os[o] = true
				}
			}
			if len(os) == 0 {
				return true
			}
			label := c.Name + "@" + a.pos(x)
			if a.onCall != nil && a.onCall(x, c, label) {
				return true
			}
			switch {
			case sinkNames[c.Name]:
				a.recordReached(os, label)
			case propagatorNames[c.Name] || propagatorNames[c.Pkg+"."+c.Name]:
			default:
				a.recordEscape(os, "call:"+label)
			}
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				a.recordEscape(a.originsOf(r), "return@"+a.pos(x))
			}
		case *ast.CompositeLit:
			for _, el := range x.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					el = kv.Value
				}
				a.recordEscape(a.originsOf(el), "composite:"+exprString(a.prog.Fset, x.Type)+"@"+a.pos(x))
			}
		}
		return true
	})

}

func newHintAnalyzer(prog *load.Program, f *load.File, scope *funcScope) *hintAnalyzer {
	return &hintAnalyzer{prog: prog, f: f, scope: scope, taint: map[string]map[origin]bool{}, roots: map[string]int{}}
}

// findSites finds the hint call sites of body, binds each to its result
// variable and adds one state per site.
func (a *hintAnalyzer) findSites(body ast.Node, nextID func() string) {
	// 1. hint call sites and their result variables
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		c := calleeOf(a.f, call)
		if !hintCallNames[c.Name] || len(call.Args) < 2 || c.Pkg != "" && !isGnarkPath(c.Pkg) {
			return true
		}
		file, line := a.prog.Pos(a.f, call)
		site := &HintSite{
			ID: nextID(), Pos: Pos{File: file, Line: line}, Function: a.scope.Name, Circuit: a.scope.Circuit,
			Call: exprString(a.prog.Fset, call.Fun), HintFunc: exprString(a.prog.Fset, call.Args[0]),
			NbOutputs: exprString(a.prog.Fset, call.Args[1]), Outputs: []*HintOutput{}, InTest: a.f.IsTest,
		}
		nb := -1
		if c.Name == "NewHintGeneric" && len(call.Args) >= 3 {
			site.NbOutputs = exprString(a.prog.Fset, call.Args[1]) + "+" + exprString(a.prog.Fset, call.Args[2])
		} else if v, ok := constInt(a.f, a.f.Pkg.Files, call.Args[1]); ok {
			nb = v
		}
		st := &hintState{site: site, nb: nb, reached: map[string][]string{}, escapes: map[string][]string{}, observed: map[string]bool{}}
		a.states = append(a.states, st)
		return true
	})
	if len(a.states) == 0 {
		return
	}
	// bind each site to its result variable
	idx := 0
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		c := calleeOf(a.f, call)
		if !hintCallNames[c.Name] || len(call.Args) < 2 || c.Pkg != "" && !isGnarkPath(c.Pkg) {
			return true
		}
		st := a.states[idx]
		idx++
		switch p := parents[call].(type) {
		case *ast.AssignStmt:
			if len(p.Rhs) == 1 && len(p.Lhs) >= 1 {
				switch lhs := p.Lhs[0].(type) {
				case *ast.Ident:
					if lhs.Name == "_" {
						st.site.OutVar = "_"
					} else {
						st.site.OutVar = lhs.Name
						st.rootKey = a.key(lhs)
						a.roots[st.rootKey] = idx - 1
					}
				default:
					st.site.OutVar = exprString(a.prog.Fset, lhs)
					st.escapes["*"] = appendUniq(st.escapes["*"], "field:"+st.site.OutVar+"@"+a.pos(p))
				}
			}
		case *ast.ValueSpec:
			if len(p.Names) >= 1 && p.Names[0].Name != "_" {
				st.site.OutVar = p.Names[0].Name
				st.rootKey = a.key(p.Names[0])
				a.roots[st.rootKey] = idx - 1
			}
		case *ast.ReturnStmt:
			st.escapes["*"] = appendUniq(st.escapes["*"], "return@"+a.pos(p))
		default:
			st.escapes["*"] = appendUniq(st.escapes["*"], "expr@"+a.pos(call))
		}
		return true
	})

}
