// Package harness writes the per-gadget PoC harness of library mode: a
// wrapper circuit whose Define calls one exported gadget (inputs as witness
// fields, outputs asserted equal to witness fields), so the circuit PoC
// templates (T-HINT-OVERRIDE, T-INVALID-ASSIGNMENT, T-PROVE-VERIFY) apply
// to a gadget that no production circuit uses, plus skipped skeletons of an
// honest test, a hint-override PoC and a differential test against the
// native reference. The file goes into the PoC worktree, never into the
// audited repository.
package harness

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
)

// Options for Generate.
type Options struct {
	// EmParams is the concrete emulated.FieldParams type substituted for a
	// gadget's type parameters (default emparams.BN254Fp).
	EmParams string
	// Curve is the gnark-crypto ecc id of the native field (default BN254).
	Curve string
	// External writes the harness as the external test package
	// (<pkg>_test) that imports the gadget's package. Use it when the
	// in-package test would import-cycle (gnark's own std packages, which
	// gnark/test and the builders import); unexported names are then out of
	// reach.
	External bool
}

// FileName is the harness file name for a gadget.
func FileName(g *inventory.Gadget) string {
	return "zkaudit_harness_" + strings.ToLower(ident(g)) + "_test.go"
}

// ident is the gadget's Go identifier for generated names: Func or
// TypeMethod.
func ident(g *inventory.Gadget) string {
	parts := strings.Split(g.Name, ".")
	return strings.Join(parts[1:], "")
}

var reTypeParams = regexp.MustCompile(`^func (?:\([^)]*\) )?\w+\[([^\]]*)\]`)

// typeParams returns the names of the gadget's type parameters.
func typeParams(sig string) []string {
	m := reTypeParams.FindStringSubmatch(sig)
	if m == nil {
		return nil
	}
	var out []string
	for _, part := range strings.Split(m[1], ",") {
		f := strings.Fields(part)
		if len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

func exported(name string) string {
	if name == "" {
		return "X"
	}
	r := []rune(name)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// Generate returns the harness file for g (gofmt-formatted).
func Generate(inv *inventory.Inventory, g *inventory.Gadget, opt Options) (string, error) {
	if opt.EmParams == "" {
		opt.EmParams = "emparams.BN254Fp"
	}
	if opt.Curve == "" {
		opt.Curve = "BN254"
	}
	pkg := strings.Split(g.Name, ".")[0]
	id := ident(g)
	qual := func(t string) string { return t }
	prefix := ""
	if opt.External {
		if g.ImportPath == "" {
			return "", fmt.Errorf("harness for %s: --external needs the gadget's import path (typed inventory)", g.Name)
		}
		prefix = pkg + "."
		qual = func(t string) string { return qualify(t, pkg) }
	}
	wrap := "wrap" + id
	tps := typeParams(g.Signature)
	subst := func(t string) string {
		for _, tp := range tps {
			t = regexp.MustCompile(`\b`+regexp.QuoteMeta(tp)+`\b`).ReplaceAllString(t, opt.EmParams)
		}
		return t
	}
	imports := map[string]bool{
		"math/big": true, "math/rand": true, "testing": true,
		g.ImportPath:                            opt.External,
		"github.com/consensys/gnark-crypto/ecc": true,
		"github.com/consensys/gnark/frontend":   true,
		"github.com/consensys/gnark/test":       true,
	}
	var fields, setup, asserts, shape, notes []string
	needField := false
	fieldType := ""
	// receiver
	callee := g.Name[len(pkg)+1:]
	if g.Receiver != "" {
		ctor := ""
		for _, o := range inv.Gadgets {
			if o.Name == pkg+".New"+g.Receiver && len(o.Params) == 1 && o.Params[0].Kind == "api" {
				ctor = "New" + g.Receiver
			}
		}
		if ctor != "" {
			setup = append(setup, fmt.Sprintf("obj := %s%s(api)", prefix, ctor))
		} else {
			setup = append(setup, fmt.Sprintf("obj := new(%s%s) // TODO: construct the %s the way callers do", prefix, g.Receiver, g.Receiver))
		}
		callee = "obj." + callee[len(g.Receiver)+1:]
	} else {
		callee = prefix + callee
		if len(tps) > 0 {
			callee += "[" + strings.Join(repeat(opt.EmParams, len(tps)), ", ") + "]"
		}
	}
	var args []string
	for _, p := range g.Params {
		f := exported(p.Name)
		t := qual(subst(p.Type))
		switch p.Kind {
		case "api":
			args = append(args, "api")
		case "field":
			needField = true
			fieldType = strings.TrimPrefix(t, "*")
			args = append(args, "f")
		case "variable":
			fields = append(fields, fmt.Sprintf("%s frontend.Variable", f))
			args = append(args, "c."+f)
		case "variables":
			fields = append(fields, fmt.Sprintf("%s %s", f, t))
			args = append(args, "c."+f)
			if strings.HasPrefix(t, "[]") {
				shape = append(shape, fmt.Sprintf("%s: make(%s, 4), // TODO: the length callers use", f, t))
			}
		case "int":
			fields = append(fields, fmt.Sprintf("%s %s `gnark:\"-\"`", f, t))
			args = append(args, "c."+f)
			def := "8"
			if t == "bool" {
				def = "false"
			}
			shape = append(shape, fmt.Sprintf("%s: %s, // TODO: the value callers use (compile-time parameter)", f, def))
		case "element":
			et := strings.TrimPrefix(t, "*")
			fields = append(fields, fmt.Sprintf("%s %s", f, et))
			if strings.HasPrefix(t, "*") {
				args = append(args, "&c."+f)
			} else {
				args = append(args, "c."+f)
			}
			if fieldType == "" {
				fieldType = strings.Replace(et, "Element", "Field", 1)
			}
		default:
			if strings.HasPrefix(t, "...") {
				notes = append(notes, fmt.Sprintf("the variadic %s (%s) is omitted from the call; add the options callers pass", p.Name, p.Type))
				continue
			}
			fields = append(fields, fmt.Sprintf("%s %s `gnark:\"-\"` // TODO: not a witness type; set it in the shape", f, t))
			args = append(args, "c."+f)
			notes = append(notes, fmt.Sprintf("parameter %s has type %s, which the harness does not know how to assign", p.Name, p.Type))
		}
	}
	var outs []string
	for _, r := range g.Results {
		o := fmt.Sprintf("out%d", r.Index)
		outs = append(outs, o)
		t := qual(subst(r.Type))
		of := fmt.Sprintf("Out%d", r.Index)
		switch {
		case r.Type == "error":
			asserts = append(asserts, fmt.Sprintf("if %s != nil {\nreturn %s\n}", o, o))
		case t == "frontend.Variable":
			fields = append(fields, of+" frontend.Variable")
			asserts = append(asserts, fmt.Sprintf("api.AssertIsEqual(%s, c.%s)", o, of))
		case strings.HasPrefix(t, "[]frontend.Variable") || regexp.MustCompile(`^\[\d+\]frontend\.Variable$`).MatchString(t):
			fields = append(fields, of+" "+t)
			asserts = append(asserts, fmt.Sprintf("for i := range c.%s {\napi.AssertIsEqual(%s[i], c.%s[i])\n}", of, o, of))
			if strings.HasPrefix(t, "[]") {
				shape = append(shape, fmt.Sprintf("%s: make(%s, 8), // TODO: the gadget's output length", of, t))
			}
		case strings.Contains(t, "emulated.Element["):
			et := strings.TrimPrefix(t, "*")
			fields = append(fields, of+" "+et)
			needField = true
			if fieldType == "" {
				fieldType = strings.Replace(et, "Element", "Field", 1)
			}
			ref := o
			if !strings.HasPrefix(t, "*") {
				ref = "&" + o
			}
			asserts = append(asserts, fmt.Sprintf("// f.AssertIsEqual compares modulo p; to test a canonical (< p) promise,\n// compare %s.Limbs with c.%s.Limbs one by one instead.\nf.AssertIsEqual(%s, &c.%s)", o, of, ref, of))
		default:
			asserts = append(asserts, fmt.Sprintf("_ = %s // TODO: %s is not a witness type; assert what the doc promises about it", o, t))
		}
	}
	if needField || fieldType != "" {
		imports["github.com/consensys/gnark/std/math/emulated"] = true
		if fieldType == "" {
			fieldType = "emulated.Field[" + opt.EmParams + "]"
		}
		setup = append([]string{fmt.Sprintf("f, err := emulated.NewField[%s](api)\nif err != nil {\nreturn err\n}\n_ = f", typeArg(fieldType))}, setup...)
	}
	if strings.Contains(strings.Join(fields, "\n")+fieldType, "emparams.") {
		imports["github.com/consensys/gnark/std/math/emulated/emparams"] = true
	}
	// hints of the gadget for the override skeleton
	var hints []string
	for _, h := range inv.Hints {
		for _, hid := range g.HintIDs {
			if h.ID == hid && !contains(hints, h.HintFunc) {
				hints = append(hints, h.HintFunc)
			}
		}
	}
	sort.Strings(hints)

	var b bytes.Buffer
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("// Code generated by gnark-inventory harness for %s (%s:%d). It belongs in\n", g.Name, g.Pos.File, g.Pos.Line)
	w("// the zk-audit PoC worktree only; edit it freely there.\n\n")
	if opt.External {
		w("package %s_test\n\n", pkg)
	} else {
		w("package %s\n\n", pkg)
	}
	if len(hints) > 0 {
		imports["github.com/consensys/gnark/constraint/solver"] = true
		imports["github.com/consensys/gnark/frontend/cs/r1cs"] = true
	}
	w("import (\n")
	for _, std := range []bool{true, false} {
		for _, imp := range sortedKeys(imports) {
			if imports[imp] && !strings.Contains(imp, ".") == std {
				w("\t%q\n", imp)
			}
		}
		if std {
			w("\n")
		}
	}
	w(")\n\n")
	w("// %s wraps %s in a circuit so the PoC templates apply: the gadget's\n", wrap, g.Name)
	w("// inputs are witness fields and its outputs are asserted equal to the\n// Out fields. A false statement is an assignment whose Out fields break\n// the gadget's doc contract.\n")
	w("//\n// Signature: %s\n", g.Signature)
	for _, n := range notes {
		w("// TODO: %s.\n", n)
	}
	w("type %s struct {\n%s\n}\n\n", wrap, strings.Join(fields, "\n"))
	w("func (c *%s) Define(api frontend.API) error {\n", wrap)
	for _, s := range setup {
		w("%s\n", s)
	}
	callExpr := fmt.Sprintf("%s(%s)", callee, strings.Join(args, ", "))
	if len(outs) > 0 {
		w("%s := %s\n", strings.Join(outs, ", "), callExpr)
	} else {
		w("%s\n", callExpr)
	}
	for _, a := range asserts {
		w("%s\n", a)
	}
	w("return nil\n}\n\n")
	w("// new%s returns the circuit shape. Set compile-time parameters and slice\n// lengths to the values the library's callers use: they change the\n// constraint system.\n", exported(wrap))
	w("func new%s() *%s {\nreturn &%s{\n%s\n}\n}\n\n", exported(wrap), wrap, wrap, strings.Join(shape, "\n"))
	field := fmt.Sprintf("ecc.%s.ScalarField()", opt.Curve)
	w("// TestHarness_%s_Honest: an honest assignment is accepted (the sanity\n// control of every PoC).\n", id)
	w("func TestHarness_%s_Honest(t *testing.T) {\n", id)
	w("t.Skip(\"zk-audit harness: fill in an honest assignment, then delete this line\")\n")
	w("a := new%s()\n// a.<input> = ...; a.Out<i> = what the doc promises\n", exported(wrap))
	w("if err := test.IsSolved(new%s(), a, %s); err != nil {\nt.Fatal(err)\n}\n}\n\n", exported(wrap), field)
	w("// TestPoC_%s_Invalid: T-INVALID-ASSIGNMENT. An assignment that breaks the\n// doc contract must be rejected; the test passes when it is accepted.\n", id)
	w("func TestPoC_%s_Invalid(t *testing.T) {\n", id)
	w("t.Skip(\"zk-audit harness: fill in the false statement, then delete this line\")\n")
	w("bad := new%s()\n// bad.Out<i> = a value the doc rules out\n", exported(wrap))
	w("if err := test.IsSolved(new%s(), bad, %s); err != nil {\nt.Fatalf(\"the gadget rejects the false statement (no bug shown): %%v\", err)\n}\n}\n\n", exported(wrap), field)
	for _, h := range hints {
		hn := exported(strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return r
			}
			return -1
		}, h))
		local := regexp.MustCompile(`^[a-zA-Z_]\w*$`).MatchString(h) && (!opt.External || ast.IsExported(h))
		if local && opt.External {
			h = prefix + h
		}
		w("// TestPoC_%s_Override%s: T-HINT-OVERRIDE on %s. The malicious hint\n// returns outputs that satisfy the constraints and break the doc contract.\n", id, hn, h)
		w("func TestPoC_%s_Override%s(t *testing.T) {\n", id, hn)
		w("t.Skip(\"zk-audit harness: write evil and the assignment, then delete this line\")\n")
		w("field := %s\n", field)
		w("ccs, err := frontend.Compile(field, r1cs.NewBuilder, new%s())\nif err != nil {\nt.Fatal(err)\n}\n", exported(wrap))
		w("w, err := frontend.NewWitness(new%s(), field) // the false statement\nif err != nil {\nt.Fatal(err)\n}\n", exported(wrap))
		w("evil := func(mod *big.Int, in, out []*big.Int) error {\nreturn nil // prover-chosen outputs\n}\n")
		if local {
			w("id := solver.GetHintID(%s)\n", h)
		} else {
			w("var id solver.HintID // TODO: %s is not in this package; find it by name with solver.GetHintName (T-HINT-OVERRIDE)\n", h)
		}
		w("if _, err := ccs.Solve(w, solver.OverrideHint(id, evil)); err != nil {\nt.Fatalf(\"attack: the malicious hint should satisfy the constraints: %%v\", err)\n}\n")
		w("if _, err := ccs.Solve(w); err == nil {\nt.Fatal(\"control: the honest hint must reject the false statement\")\n}\n}\n\n")
	}
	w("// TestDiff_%s compares the gadget with its native reference on random\n// and edge inputs (zero, one, the bounds the doc states, r - 1). Each case\n// assigns the inputs and the native outputs; IsSolved must accept it.\n", id)
	w("func TestDiff_%s(t *testing.T) {\n", id)
	w("t.Skip(\"zk-audit harness: name the native reference, then delete this line\")\n")
	w("field := %s\n", field)
	w("rng := rand.New(rand.NewSource(1))\n")
	w("edges := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(field, big.NewInt(1))}\n")
	w("for i := 0; i < 64+len(edges); i++ {\n")
	w("a := new%s()\n// inputs: edges[i-64] for i >= 64, else random values below the documented bounds (rng)\n// outputs: the native reference (the library's Go code, gnark-crypto or math/big)\n_, _ = rng, edges\n", exported(wrap))
	w("if err := test.IsSolved(new%s(), a, field); err != nil {\nt.Fatalf(\"case %%d: the gadget and the native reference disagree: %%v\", i, err)\n}\n}\n}\n", exported(wrap))
	src, err := format.Source(b.Bytes())
	if err != nil {
		return b.String(), fmt.Errorf("harness for %s: generated code does not parse: %w", g.Name, err)
	}
	return string(src), nil
}

func typeArg(fieldType string) string {
	if i := strings.Index(fieldType, "["); i >= 0 && strings.HasSuffix(fieldType, "]") {
		return fieldType[i+1 : len(fieldType)-1]
	}
	return fieldType
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// qualify prefixes the exported identifiers of a type expression that are
// not already package-qualified with pkg ("*Accumulator" becomes
// "*gadgets.Accumulator"; "frontend.Variable" stays).
func qualify(t, pkg string) string {
	var b strings.Builder
	r := []rune(t)
	for i := 0; i < len(r); {
		if unicode.IsLetter(r[i]) || r[i] == '_' {
			j := i
			for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '_') {
				j++
			}
			word := string(r[i:j])
			prevDot := i > 0 && r[i-1] == '.'
			nextDot := j < len(r) && r[j] == '.'
			if unicode.IsUpper(r[i]) && !prevDot && !nextDot {
				b.WriteString(pkg + ".")
			}
			b.WriteString(word)
			i = j
			continue
		}
		b.WriteRune(r[i])
		i++
	}
	return b.String()
}
