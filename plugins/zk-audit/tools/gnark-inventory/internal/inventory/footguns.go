package inventory

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
)

// Rule is one footgun detector. IDs are referenced by the `Seed:` field of
// attack vectors and by gnark-api-footguns.md; kblint checks they exist.
type Rule struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Note  string `json:"note"`
}

// Rules lists every detector, in report order.
var Rules = []Rule{
	{"FG-HINT-UNREACHED", "Hint output never reaches a constraint", "The prover chooses hint outputs. An output that reaches no Assert*/ToBinary/range check/recomposition in this function is unconstrained unless a caller binds it."},
	{"FG-HINT-ESCAPES", "Hint output leaves the function unconstrained", "The output is returned, stored or passed on before any constraint; check that every consumer binds it."},
	{"FG-DIV-UNCHECKED", "api.DivUnchecked", "For 0/0 the R1CS output is unconstrained (frontend/api.go). Prove the denominator is non-zero or use api.Div."},
	{"FG-CMP-UNBOUNDED", "Comparison on possibly unbounded or wrapped operands", "api.Cmp / AssertIsLessOrEqual / cmp.IsLess compare canonical values in [0, r); a Sub result r-k compares as huge. Bound operands first."},
	{"FG-OMIT-MODULUS-CHECK", "bits.OmitModulusCheck", "Full-width decomposition without the modulus check accepts both a and a+r (CVE-2023-44378 shape)."},
	{"FG-UNCONSTRAINED-BITS", "bits / bitslice unconstrained option", "WithUnconstrainedOutputs / WithUnconstrainedInputs drop the booleanity (or digit) constraints; something else must constrain them."},
	{"FG-IGNORE-UNCONSTRAINED-INPUTS", "frontend.IgnoreUnconstrainedInputs", "Compiles circuits whose inputs appear in no constraint; such public inputs are not bound by the proof."},
	{"FG-SELECTOR", "Selector / multiplexer gadget", "Check the selector's domain and who controls it; out-of-range selectors fail, but a prover-controlled selector picks any branch."},
	{"FG-GATED-ASSERT", "Flag-gated assertion", "AssertIsEqual(Mul(flag, a-b), 0) or an asserted Select holds trivially when the flag is 0; check the flag is bound."},
	{"FG-GO-BRANCH-ON-WITNESS", "Go control flow or Go == on witness values", "Go if/switch/== in circuit code runs at compile time on placeholder values, not on the witness."},
	{"FG-DISCARDED-PREDICATE", "Predicate result discarded", "An Is*/Cmp call whose result is never asserted adds no check (GHSA-fwf3 shape: IsOnTwist computed and dropped)."},
	{"FG-EMULATED-WITNESS", "emulated.Element in the witness", "Witness limbs are width-checked on first use but the value may be >= the emulated modulus; use AssertIsInRange / ReduceStrict where canonicity matters."},
	{"FG-EMULATED-LIMBS", "Direct access to emulated Element.Limbs", "Using Limbs in native arithmetic bypasses the emulated width checks (zkSecurity gnark-std 0b)."},
	{"FG-EMULATED-VALUEOF-IN-CIRCUIT", "emulated.ValueOf inside circuit code", "ValueOf is for witness assignment; in-circuit constants should use Field.NewElement."},
	{"FG-VK-AS-WITNESS", "Recursion verifying key as witness", "ValueOfVerifyingKey makes the inner VK a witness: bind it to a constant (ValueOfVerifyingKeyFixed) or a public hash."},
	{"FG-DEV-SETUP", "Single-party or unsafe setup outside tests", "groth16.Setup / unsafekzg.NewSRS produce toxic waste known to the caller; production keys need an MPC ceremony or a public SRS."},
	{"FG-COMMIT", "In-circuit commitment (Committer / multicommit)", "Groth16 commitments: >1 commitment unsound before v0.11.0, commitments to secrets are not hiding (CVE-2024-45039/45040); Solidity needs WithProverTargetSolidityVerifier."},
	{"FG-MIMC", "MiMC hasher", "MiMC (Miyaguchi-Preneel) has length extension and no domain separation; fix the input length or add a domain tag."},
	{"FG-MERKLE", "Merkle proof verification", "std/accumulator/merkle applies no domain separation; the leaf is Path[0] and must be bound to its preimage; the root must be public or bound."},
	{"FG-SIGNATURE", "In-circuit signature verification", "Before v0.14.0 S was not checked < order (CVE-2025-57801); never derive nullifiers from (R, S)."},
	{"FG-SKIP-TAG", "Witness-typed field tagged gnark:\"-\"", "The field is not part of the witness; any value it holds is fixed at compile time."},
	{"FG-UNTRUSTED-DESERIALIZE", "Key / proof / witness deserialization", "Check the bytes' source and size limits; crafted VKs or proofs caused OOM before v0.11.1 (CVE-2024-50354)."},
	{"FG-HASH-TO-FIELD", "Custom hash-to-field for commitments", "Prover, Go verifier and Solidity verifier must use the same hash-to-field function."},
}

func ruleNote(id string) string {
	for _, r := range Rules {
		if r.ID == id {
			return r.Note
		}
	}
	return ""
}

// RuleIDs returns the set of known rule ids.
func RuleIDs() map[string]bool {
	m := map[string]bool{}
	for _, r := range Rules {
		m[r.ID] = true
	}
	return m
}

type footgunCtx struct {
	// defs maps a local name to the expression it was last defined from
	// (`x := expr`) in the current function, for one-step operand tracing.
	defs     map[string]ast.Expr
	prog     *load.Program
	f        *load.File
	scope    *funcScope
	circuits map[string]*Circuit
	out      *[]*Footgun
}

func (c *footgunCtx) hit(id string, n ast.Node, note string) {
	file, line := c.prog.Pos(c.f, n)
	fg := &Footgun{ID: id, Pos: Pos{File: file, Line: line}, Snippet: exprString(c.prog.Fset, n), InTest: c.f.IsTest}
	if c.scope != nil {
		fg.Function = c.scope.Name
		fg.Circuit = c.scope.Circuit
	}
	fg.Note = ruleNote(id)
	if note != "" {
		fg.Note = note + " " + fg.Note
	}
	*c.out = append(*c.out, fg)
}

var rePredicate = regexp.MustCompile(`^(Is[A-Z]\w*|Cmp)$`)

// scanFootguns runs every call- and statement-level detector over one file.
func scanFootguns(prog *load.Program, f *load.File, circuits map[string]*Circuit, out *[]*Footgun) {
	ctx := &footgunCtx{prog: prog, f: f, circuits: circuits, out: out}
	for _, d := range f.AST.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ctx.scope = newFuncScope(f, fd)
		if c, ok := circuits[scopeKey(f, ctx.scope.RecvType)]; ok {
			ctx.scope.Circuit = c.Name
		}
		// closures that take an API parameter extend the scope
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if fl, ok := n.(*ast.FuncLit); ok {
				addAPIParams(f, fl.Type, ctx.scope.APINames)
			}
			return true
		})
		ctx.scanBody(fd.Body)
	}
}

func scopeKey(f *load.File, typeName string) string {
	return f.Pkg.Dir + "|" + typeName
}

func (c *footgunCtx) scanBody(body *ast.BlockStmt) {
	f := c.f
	c.defs = map[string]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
			for i, l := range as.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					c.defs[id.Name] = as.Rhs[i]
				}
			}
		}
		return true
	})
	inCircuit := c.scope.inCircuitCode()
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			c.call(x, inCircuit)
		case *ast.ExprStmt:
			if call, ok := x.X.(*ast.CallExpr); ok && inCircuit {
				cl := calleeOf(f, call)
				if cl.Recv != nil && rePredicate.MatchString(cl.Name) && c.returnsValue(call) {
					c.hit("FG-DISCARDED-PREDICATE", call, "")
				}
			}
		case *ast.IfStmt:
			if inCircuit && !c.isConstantCheck(x.Init, x.Cond) && c.mentionsWitness(x.Cond) {
				c.hit("FG-GO-BRANCH-ON-WITNESS", x.Cond, "Go if on a witness value.")
			}
		case *ast.SwitchStmt:
			if inCircuit && x.Tag != nil && c.mentionsWitness(x.Tag) {
				c.hit("FG-GO-BRANCH-ON-WITNESS", x.Tag, "Go switch on a witness value.")
			}
		case *ast.BinaryExpr:
			if inCircuit && (x.Op == token.EQL || x.Op == token.NEQ) && c.isWitnessValue(x.X) && c.isWitnessValue(x.Y) {
				c.hit("FG-GO-BRANCH-ON-WITNESS", x, "Go == / != compares interface values at compile time.")
			}
		case *ast.SelectorExpr:
			if inCircuit && x.Sel.Name == "Limbs" && c.isEmulatedElement(x.X) {
				c.hit("FG-EMULATED-LIMBS", x, "")
			}
		case *ast.TypeAssertExpr:
			if x.Type != nil && isPkgSel(f, x.Type, pkgFrontend, "Committer") {
				c.hit("FG-COMMIT", x, "Type assertion to frontend.Committer.")
			}
		}
		return true
	})
}

func (c *footgunCtx) returnsValue(call *ast.CallExpr) bool {
	if c.f.Pkg.Info == nil {
		return true
	}
	t := c.f.Pkg.Info.TypeOf(call)
	if t == nil {
		return true
	}
	if tup, ok := t.(*types.Tuple); ok {
		return tup.Len() > 0
	}
	return true
}

func (c *footgunCtx) isEmulatedElement(e ast.Expr) bool {
	if c.f.Pkg.Info != nil {
		if t := c.f.Pkg.Info.TypeOf(e); t != nil {
			return isNamed(t, pkgEmulated, "Element")
		}
	}
	return importsPath(c.f, pkgEmulated)
}

func (c *footgunCtx) isConstantCheck(init ast.Stmt, cond ast.Expr) bool {
	found := false
	check := func(n ast.Node) {
		if n == nil {
			return
		}
		ast.Inspect(n, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				name := calleeOf(c.f, call).Name
				if name == "ConstantValue" || name == "IsConstant" || name == "IsBoolean" {
					found = true
				}
			}
			return !found
		})
	}
	check(init)
	check(cond)
	return found
}

// isWitnessValue reports whether e is (in types mode) a frontend.Variable,
// or (in syntax mode) a selector on the circuit receiver naming a witness
// field.
func (c *footgunCtx) isWitnessValue(e ast.Expr) bool {
	if c.f.Pkg.Typed {
		return isVariableExpr(c.f, e)
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || c.scope == nil || c.scope.Circuit == "" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != c.scope.RecvName {
		return false
	}
	ci := c.circuits[scopeKey(c.f, c.scope.RecvType)]
	return ci != nil && ci.hasTopField(sel.Sel.Name)
}

func (ci *Circuit) hasTopField(name string) bool {
	for _, gs := range [][]*Group{ci.Witness.Public, ci.Witness.Secret} {
		for _, g := range gs {
			top := g.GoPath
			if i := strings.IndexAny(top, ".["); i >= 0 {
				top = top[:i]
			}
			if top == name {
				return true
			}
		}
	}
	return false
}

func (c *footgunCtx) mentionsWitness(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			// a call result is a fresh value; a call on a Variable in a Go
			// condition is unusual but not what this detector targets
			_ = x
		case ast.Expr:
			if c.isWitnessValue(x) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func (c *footgunCtx) call(call *ast.CallExpr, inCircuit bool) {
	f := c.f
	cl := calleeOf(f, call)
	switch {
	// ---- package-qualified calls
	case cl.Pkg == pkgBits && cl.Name == "OmitModulusCheck":
		c.hit("FG-OMIT-MODULUS-CHECK", call, "")
	case (cl.Pkg == pkgBits || cl.Pkg == pkgBitslice) && (cl.Name == "WithUnconstrainedOutputs" || cl.Name == "WithUnconstrainedInputs"):
		c.hit("FG-UNCONSTRAINED-BITS", call, "")
	case cl.Pkg == pkgFrontend && cl.Name == "IgnoreUnconstrainedInputs":
		c.hit("FG-IGNORE-UNCONSTRAINED-INPUTS", call, "")
	case cl.Pkg == pkgCmp && (cl.Name == "IsLess" || cl.Name == "IsLessOrEqual"):
		c.cmpHit(call)
	case cl.Pkg == pkgSelector && (cl.Name == "Mux" || cl.Name == "Map" || cl.Name == "BinaryMux" || cl.Name == "KeyDecoder" ||
		cl.Name == "Decoder" || cl.Name == "Partition" || cl.Name == "Slice"):
		c.hit("FG-SELECTOR", call, "selector."+cl.Name+".")
	case (cl.Pkg == pkgGroth16 && cl.Name == "Setup") || (cl.Pkg == pkgUnsafeKZ && cl.Name == "NewSRS"):
		if !f.IsTest {
			c.hit("FG-DEV-SETUP", call, "")
		}
	case cl.Pkg == pkgMulti && cl.Name == "WithCommitment":
		c.hit("FG-COMMIT", call, "multicommit.WithCommitment.")
	case (cl.Pkg == pkgRecG16 || cl.Pkg == pkgRecPlonk || cl.Pkg == pkgPedersen) && cl.Name == "ValueOfVerifyingKey":
		c.hit("FG-VK-AS-WITNESS", call, "")
	case cl.Pkg == pkgMiMC && cl.Name == "NewMiMC":
		c.hit("FG-MIMC", call, "")
	case cl.Pkg == pkgEdDSA && cl.Name == "Verify":
		c.hit("FG-SIGNATURE", call, "eddsa.Verify.")
	case cl.Pkg == pkgEmulated && cl.Name == "ValueOf" && inCircuit:
		c.hit("FG-EMULATED-VALUEOF-IN-CIRCUIT", call, "")
	case (cl.Pkg == pkgBackend && (cl.Name == "WithProverHashToFieldFunction" || cl.Name == "WithVerifierHashToFieldFunction")) ||
		(cl.Pkg == pkgSolidity && cl.Name == "WithHashToFieldFunction"):
		c.hit("FG-HASH-TO-FIELD", call, "")
	}
	if cl.Recv == nil {
		return
	}
	// ---- method calls
	switch cl.Name {
	case "DivUnchecked":
		if apiLike(f, c.scope, cl.Recv) {
			c.hit("FG-DIV-UNCHECKED", call, "")
		}
	case "Cmp", "AssertIsLessOrEqual", "IsLess":
		if apiLike(f, c.scope, cl.Recv) {
			c.cmpHit(call)
		}
	case "Lookup2":
		if apiLike(f, c.scope, cl.Recv) {
			c.hit("FG-SELECTOR", call, "api.Lookup2.")
		}
	case "AssertIsEqual":
		if inCircuit && len(call.Args) == 2 && c.gated(call) {
			c.hit("FG-GATED-ASSERT", call, "")
		}
	case "Commit":
		if inCircuit && len(call.Args) >= 1 && !f.IsTest {
			if _, isSel := cl.Recv.(*ast.TypeAssertExpr); isSel || c.isCommitter(cl.Recv) {
				c.hit("FG-COMMIT", call, "Committer.Commit.")
			}
		}
	case "VerifyProof":
		if importsPath(f, pkgMerkle) && len(call.Args) == 3 {
			c.hit("FG-MERKLE", call, "")
		}
	case "Verify":
		if importsPath(f, pkgECDSA) && inCircuit {
			c.hit("FG-SIGNATURE", call, "ecdsa PublicKey.Verify.")
		}
	case "ReadFrom", "UnsafeReadFrom", "ReadDump":
		if !f.IsTest && (importsPath(f, pkgGroth16) || importsPath(f, pkgPlonk) || importsPath(f, pkgWitness)) {
			c.hit("FG-UNTRUSTED-DESERIALIZE", call, "")
		}
	}
}

func (c *footgunCtx) isCommitter(e ast.Expr) bool {
	if c.f.Pkg.Info == nil {
		return false
	}
	t := c.f.Pkg.Info.TypeOf(e)
	return t != nil && isNamed(t, pkgFrontend, "Committer")
}

// gated reports AssertIsEqual(Mul(.., Sub(..)), 0) and asserted Selects.
func (c *footgunCtx) gated(call *ast.CallExpr) bool {
	isZero := func(e ast.Expr) bool {
		v, ok := intLit(e)
		return ok && v == 0
	}
	has := func(e ast.Expr, name string) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok && calleeOf(c.f, ce).Name == name {
				found = true
			}
			return !found
		})
		return found
	}
	topIs := func(e ast.Expr, name string) bool {
		ce, ok := e.(*ast.CallExpr)
		return ok && calleeOf(c.f, ce).Name == name
	}
	a, b := call.Args[0], call.Args[1]
	if (topIs(a, "Mul") && has(a, "Sub") && isZero(b)) || (topIs(b, "Mul") && has(b, "Sub") && isZero(a)) {
		return true
	}
	return topIs(a, "Select") || topIs(b, "Select")
}

func (c *footgunCtx) cmpHit(call *ast.CallExpr) {
	note := ""
	for _, a := range call.Args {
		found := false
		if id, ok := a.(*ast.Ident); ok && c.defs[id.Name] != nil {
			a = c.defs[id.Name]
		}
		ast.Inspect(a, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok {
				if nm := calleeOf(c.f, ce).Name; nm == "Sub" || nm == "Neg" {
					found = true
				}
			}
			return !found
		})
		if found {
			note = "An operand is a Sub/Neg result and wraps below zero."
		}
	}
	c.hit("FG-CMP-UNBOUNDED", call, note)
}

// witnessFootguns adds hits derived from circuit layouts.
func witnessFootguns(prog *load.Program, circuits []*Circuit, out *[]*Footgun) {
	for _, ci := range circuits {
		seen := map[string]bool{}
		for _, gs := range [][]*Group{ci.Witness.Public, ci.Witness.Secret} {
			for _, g := range gs {
				if g.Note != emulatedLimbsNote {
					continue
				}
				top := g.GoPath
				if i := strings.IndexAny(top, ".["); i >= 0 {
					top = top[:i]
				}
				if seen[top] {
					continue
				}
				seen[top] = true
				*out = append(*out, &Footgun{ID: "FG-EMULATED-WITNESS", Pos: g.Decl, Circuit: ci.Name,
					Snippet: ci.Name + "." + top, Note: ruleNote("FG-EMULATED-WITNESS"), InTest: ci.InTest})
			}
		}
		for _, o := range ci.Witness.Omit {
			*out = append(*out, &Footgun{ID: "FG-SKIP-TAG", Pos: o.Decl, Circuit: ci.Name,
				Snippet: ci.Name + "." + o.GoPath + " " + o.Type, Note: ruleNote("FG-SKIP-TAG"), InTest: ci.InTest})
		}
		for _, p := range ci.Witness.VKAt {
			*out = append(*out, &Footgun{ID: "FG-VK-AS-WITNESS", Pos: p, Circuit: ci.Name,
				Snippet: ci.Name + " verifying key field", Note: "Verifying key fields are witness leaves. " + ruleNote("FG-VK-AS-WITNESS"), InTest: ci.InTest})
		}
	}
	_ = prog
}
