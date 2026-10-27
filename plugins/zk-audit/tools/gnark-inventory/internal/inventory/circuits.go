package inventory

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
)

// maxExpand bounds how many leaves an array of structs is expanded into
// before it is summarised as one group.
const maxExpand = 512

// findCircuits returns every type with a `Define(frontend.API) error` method.
func findCircuits(prog *load.Program) []*Circuit {
	var out []*Circuit
	for _, f := range prog.Files {
		for _, d := range f.AST.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Define" || !isDefineSig(f, fd.Type) {
				continue
			}
			r := fd.Recv.List[0]
			name := recvTypeName(r.Type)
			if name == "" {
				continue
			}
			_, ptr := r.Type.(*ast.StarExpr)
			c := &Circuit{
				Name:        name,
				Package:     pkgLabel(f),
				InTest:      f.IsTest,
				PointerRecv: ptr,
				HintIDs:     []string{},
				FootgunIDs:  []string{},
			}
			c.Define.File, c.Define.Line = prog.Pos(f, fd)
			c.Witness = buildWitness(prog, f, name, &c.Decl)
			if !ptr {
				c.Witness.Notes = append(c.Witness.Notes, "Define has a value receiver; frontend.Compile requires a pointer receiver")
			}
			out = append(out, c)
		}
	}
	return out
}

func pkgLabel(f *load.File) string {
	if f.Pkg.PkgPath != "" {
		return f.Pkg.PkgPath
	}
	dir := strings.TrimSuffix(f.Rel, "/"+lastElem(f.Rel))
	if dir == f.Rel {
		dir = "."
	}
	return dir + " (" + f.Pkg.Name + ")"
}

func lastElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isDefineSig(f *load.File, ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) != 1 || ft.Results == nil || len(ft.Results.List) != 1 {
		return false
	}
	p := ft.Params.List[0]
	if len(p.Names) > 1 || !isAPIType(f, p.Type) {
		return false
	}
	r := ft.Results.List[0]
	id, ok := r.Type.(*ast.Ident)
	return ok && id.Name == "error" && len(r.Names) <= 1
}

// ---------------------------------------------------------------- witness

type layout struct {
	w       *Witness
	fset    *token.FileSet
	rootRel string
}

func (l *layout) add(vis string, g *Group) {
	if vis == "public" {
		l.w.Public = append(l.w.Public, g)
	} else {
		l.w.Secret = append(l.w.Secret, g)
	}
}

type mark struct{ pub, sec int }

func (l *layout) mark() mark { return mark{len(l.w.Public), len(l.w.Secret)} }

// since returns the groups appended after m.
func (l *layout) since(m mark) []*Group {
	out := append([]*Group{}, l.w.Public[m.pub:]...)
	return append(out, l.w.Secret[m.sec:]...)
}

// attribute sets Decl on groups appended since m that have no in-repo
// position yet (types from other modules resolve to absolute paths).
func (l *layout) attribute(m mark, p Pos, force bool) {
	if !inRepo(p) {
		return
	}
	for _, g := range l.since(m) {
		if force || !inRepo(g.Decl) {
			g.Decl = p
		}
	}
}

// inRepo reports whether p points into the target repository (types from
// other modules resolve to absolute paths, syntax-mode std shapes to "(gnark)").
func inRepo(p Pos) bool {
	return p.File != "" && !strings.HasPrefix(p.File, "/") && !strings.HasPrefix(p.File, "(gnark)")
}

const emulatedLimbsNote = "emulated.Element limbs: count = NbLimbs of the field parameters for the native field; limbs are width-checked on first use, the value is not reduced below the modulus"

func (l *layout) noteLimbs(m mark) {
	for _, g := range l.since(m) {
		if strings.HasSuffix(g.GoPath, "Limbs") {
			g.Note = emulatedLimbsNote
		}
	}
}

func (l *layout) notePointer(m mark, goPath string) {
	gs := l.since(m)
	if len(gs) == 0 {
		return
	}
	for _, g := range gs {
		if g.Note == "" {
			g.Note = "behind pointer " + goPath + ": contributes leaves only if non-nil when the circuit is compiled"
		}
	}
}

func (l *layout) note(format string, a ...any) {
	l.w.Notes = append(l.w.Notes, fmt.Sprintf(format, a...))
}

// finish computes start offsets and static counts.
func (w *Witness) finish() {
	w.NbPublic = offsets(w.Public)
	w.NbSecret = offsets(w.Secret)
}

func offsets(gs []*Group) int {
	n := 0
	expr := ""
	for _, g := range gs {
		if expr == "" {
			g.Start = n
			g.StartExpr = strconv.Itoa(n)
		} else {
			g.Start = -1
			g.StartExpr = expr
		}
		if g.Len < 0 {
			term := "len(" + g.GoPath + ")"
			if g.PerElem > 0 {
				term = strconv.Itoa(g.PerElem) + "*len(" + strings.TrimSuffix(g.GoPath, "[i]") + ")"
			}
			if g.Kind == "opaque" {
				term = "?(" + g.GoPath + ")"
			}
			if expr == "" {
				if n == 0 {
					expr = term
				} else {
					expr = strconv.Itoa(n) + " + " + term
				}
			} else {
				expr = expr + " + " + term
			}
			continue
		}
		if expr == "" {
			n += g.Len
		} else {
			expr = expr + " + " + strconv.Itoa(g.Len)
		}
	}
	if expr != "" {
		return -1
	}
	return n
}

func buildWitness(prog *load.Program, f *load.File, typeName string, decl *Pos) *Witness {
	w := &Witness{Resolved: true, Public: []*Group{}, Secret: []*Group{}, Omit: []*Omitted{}, Notes: []string{}}
	l := &layout{w: w, fset: prog.Fset}
	if f.Pkg.Typed && f.Pkg.Types != nil {
		if obj, ok := f.Pkg.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
			p := prog.Fset.Position(obj.Pos())
			decl.File, decl.Line = relTo(prog, p.Filename), p.Line
			w.Source = "types"
			tw := &typeWalker{l: l, prog: prog, seen: map[types.Type]int{}}
			tw.walk(obj.Type(), "", "", "unset", 0)
			w.finish()
			return w
		}
	}
	w.Source = "syntax"
	sw := newSyntaxWalker(prog, l, f)
	ts, tf := sw.lookupLocal(f.Pkg, typeName)
	if ts == nil {
		w.Resolved = false
		l.note("type %s not found in package syntax", typeName)
		w.finish()
		return w
	}
	decl.File, decl.Line = prog.Pos(tf, ts)
	sw.walkType(tf, ts.Type, "", "", "unset", 0)
	w.finish()
	return w
}

func relTo(prog *load.Program, abs string) string {
	for _, f := range prog.Files {
		if f.Abs == abs {
			return f.Rel
		}
	}
	return abs
}

func joinName(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "_" + child
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// tagInfo parses a gnark struct tag the way frontend/schema does.
type tagInfo struct {
	omit    bool
	name    string
	vis     string // "", "public", "secret"
	present bool
}

func parseGnarkTag(raw string) tagInfo {
	tag, ok := reflect.StructTag(raw).Lookup("gnark")
	if !ok {
		return tagInfo{}
	}
	ti := tagInfo{present: true}
	if tag == "-" {
		ti.omit = true
		return ti
	}
	name, opts, _ := strings.Cut(tag, ",")
	if validTagName(name) {
		ti.name = name
	}
	opts = strings.TrimSpace(opts)
	// frontend/schema checks secret before public
	switch {
	case hasOpt(opts, "secret"):
		ti.vis = "secret"
	case hasOpt(opts, "public"):
		ti.vis = "public"
	}
	return ti
}

func hasOpt(opts, o string) bool {
	for _, x := range strings.Split(opts, ",") {
		if strings.TrimSpace(x) == o {
			return true
		}
	}
	return false
}

func validTagName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
		case !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c > 127):
			return false
		}
	}
	return true
}

// childVisibility applies the schema rule: a tag overrides, otherwise the
// parent's visibility is inherited; a set parent with a different child is a
// compile error.
func childVisibility(l *layout, parent string, ti tagInfo, path string) string {
	v := parent
	if ti.vis != "" {
		v = ti.vis
	}
	if parent != "unset" && v != parent {
		l.note("conflicting visibility at %s: parent is %s, field is %s (frontend.Compile fails)", path, parent, v)
	}
	return v
}

func leafVis(v string) string {
	if v == "public" {
		return "public"
	}
	return "secret"
}

// ---------------------------------------------------------------- types walker

type typeWalker struct {
	l    *layout
	prog *load.Program
	seen map[types.Type]int
}

func (tw *typeWalker) pos(p token.Pos) Pos {
	if !p.IsValid() {
		return Pos{}
	}
	pp := tw.prog.Fset.Position(p)
	return Pos{File: relTo(tw.prog, pp.Filename), Line: pp.Line}
}

func isVariableType(t types.Type) bool { return isNamed(t, pkgFrontend, "Variable") }

// countLeaves returns the static leaf count of t, or -1 if dynamic.
func countLeaves(t types.Type, depth int) int {
	if depth > 24 {
		return -1
	}
	if isVariableType(t) {
		return 1
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		n := 0
		for i := 0; i < u.NumFields(); i++ {
			if parseGnarkTag(u.Tag(i)).omit {
				continue
			}
			c := countLeaves(u.Field(i).Type(), depth+1)
			if c < 0 {
				return -1
			}
			n += c
		}
		return n
	case *types.Array:
		c := countLeaves(u.Elem(), depth+1)
		if c < 0 {
			return -1
		}
		return c * int(u.Len())
	case *types.Slice:
		if countLeaves(u.Elem(), depth+1) == 0 {
			return 0
		}
		return -1
	case *types.Pointer:
		return countLeaves(u.Elem(), depth+1)
	}
	return 0
}

func (tw *typeWalker) walk(t types.Type, goPath, name, vis string, depth int) {
	l := tw.l
	if depth > 24 {
		l.note("type nesting deeper than 24 at %s; layout truncated", goPath)
		l.w.Resolved = false
		return
	}
	if isVariableType(t) {
		l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: "frontend.Variable", Kind: "variable", Len: 1})
		return
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		emulated := isNamed(t, pkgEmulated, "Element")
		for i := 0; i < u.NumFields(); i++ {
			fld := u.Field(i)
			ti := parseGnarkTag(u.Tag(i))
			fpath := joinPath(goPath, fld.Name())
			if ti.omit {
				if p := tw.pos(fld.Pos()); inRepo(p) && countLeaves(fld.Type(), 0) != 0 {
					l.w.Omit = append(l.w.Omit, &Omitted{GoPath: fpath, Type: typeStr(fld.Type()), Decl: p})
				}
				continue
			}
			if fld.Embedded() {
				// schema walks embedded fields inline: no path element, tag ignored
				if ti.present && !ti.omit {
					l.note("embedded field %s has a gnark tag; frontend/schema ignores tags on embedded fields, so its leaves keep the parent's visibility (%s)", fpath, leafVis(vis))
				}
				m := l.mark()
				tw.walk(fld.Type(), fpath, name, vis, depth+1)
				l.attribute(m, tw.pos(fld.Pos()), depth == 0)
				continue
			}
			nm := fld.Name()
			if ti.name != "" {
				nm = ti.name
			}
			cv := childVisibility(l, vis, ti, fpath)
			nleaves := countLeaves(fld.Type(), 0)
			if !fld.Exported() && nleaves != 0 {
				l.note("unexported field %s holds witness leaves; frontend.Compile cannot set it (\"can't set val\")", fpath)
			}
			if isNamed(fld.Type(), pkgRecG16, "VerifyingKey") || isNamed(fld.Type(), pkgRecPlonk, "VerifyingKey") {
				l.w.VKAt = append(l.w.VKAt, tw.pos(fld.Pos()))
				l.note("field %s is a recursion VerifyingKey: the inner VK is part of the witness", fpath)
			}
			m := l.mark()
			tw.walk(fld.Type(), fpath, joinName(name, nm), cv, depth+1)
			if emulated && fld.Name() == "Limbs" {
				l.noteLimbs(m)
			}
			l.attribute(m, tw.pos(fld.Pos()), depth == 0)
		}
	case *types.Array:
		elem := u.Elem()
		n := int(u.Len())
		if isVariableType(elem) {
			l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: typeStr(t), Kind: "array", Len: n})
			return
		}
		k := countLeaves(elem, 0)
		if k == 0 {
			return
		}
		if k > 0 && n*k > maxExpand {
			l.add(leafVis(vis), &Group{Name: name + "_{i}", GoPath: goPath + "[i]", Type: typeStr(t), Kind: "array", Len: n * k,
				Note: fmt.Sprintf("%d elements x %d leaves, element-major order", n, k)})
			return
		}
		for i := 0; i < n; i++ {
			tw.walk(elem, fmt.Sprintf("%s[%d]", goPath, i), joinName(name, strconv.Itoa(i)), vis, depth+1)
		}
	case *types.Slice:
		elem := u.Elem()
		if isVariableType(elem) {
			l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: typeStr(t), Kind: "slice", Len: -1,
				Note: "length fixed by the slice assigned before Compile; an empty slice is ignored with a warning"})
			return
		}
		k := countLeaves(elem, 0)
		if k == 0 {
			return
		}
		l.add(leafVis(vis), &Group{Name: name + "_{i}", GoPath: goPath + "[i]", Type: typeStr(t), Kind: "slice", Len: -1, PerElem: max(k, 0),
			Note: fmt.Sprintf("slice of %s, %s leaves per element, element-major order", typeStr(elem), countStr(k))})
	case *types.Pointer:
		m := l.mark()
		tw.walk(u.Elem(), goPath, name, vis, depth+1)
		l.notePointer(m, goPath)
	case *types.Interface:
		l.note("interface field %s (%s): walked through its dynamic value at compile time; nil contributes no leaves", goPath, typeStr(t))
	case *types.Basic:
		if u.Kind() == types.Invalid {
			l.w.Resolved = false
			l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: "invalid", Kind: "opaque", Len: -1, Note: "type did not resolve"})
		}
	}
}

func countStr(k int) string {
	if k < 0 {
		return "a dynamic number of"
	}
	return strconv.Itoa(k)
}

func typeStr(t types.Type) string {
	return types.TypeString(t, func(p *types.Package) string { return p.Name() })
}

// ---------------------------------------------------------------- syntax walker

// knownStd holds the witness-relevant shape of common gnark std types, used
// only when type information is unavailable. Shapes are copied from gnark
// v0.16.4 (paths in the comment of each entry).
var knownStd = map[string]string{
	// std/algebra/native/twistededwards/twistededwards.go
	gnarkRoot + "/std/algebra/native/twistededwards": `package twistededwards
import "github.com/consensys/gnark/frontend"
type Point struct { X, Y frontend.Variable }`,
	// std/signature/eddsa/eddsa.go
	pkgEdDSA: `package eddsa
import ("github.com/consensys/gnark/frontend"; "github.com/consensys/gnark/std/algebra/native/twistededwards")
type PublicKey struct { A twistededwards.Point }
type Signature struct { R twistededwards.Point; S frontend.Variable }`,
	// std/math/emulated/element.go (unexported fields omitted)
	pkgEmulated: `package emulated
import "github.com/consensys/gnark/frontend"
type Element[T any] struct { Limbs []frontend.Variable }`,
	// std/algebra/emulated/sw_emulated/point.go
	gnarkRoot + "/std/algebra/emulated/sw_emulated": `package sw_emulated
import "github.com/consensys/gnark/std/math/emulated"
type AffinePoint[B any] struct { X, Y emulated.Element[B] }`,
	// std/signature/ecdsa/ecdsa.go
	pkgECDSA: `package ecdsa
import ("github.com/consensys/gnark/std/math/emulated"; "github.com/consensys/gnark/std/algebra/emulated/sw_emulated")
type Signature[S any] struct { R, S emulated.Element[S] }
type PublicKey[B, S any] sw_emulated.AffinePoint[B]`,
	// std/accumulator/merkle/verify.go
	pkgMerkle: `package merkle
import "github.com/consensys/gnark/frontend"
type MerkleProof struct { RootHash frontend.Variable; Path []frontend.Variable }`,
	// std/math/uints/bytes.go, uint8.go
	gnarkRoot + "/std/math/uints": `package uints
import "github.com/consensys/gnark/frontend"
type U8 struct { Val frontend.Variable; internal bool }
type U32 [4]U8
type U64 [8]U8`,
}

func knownPackages(fset *token.FileSet) map[string]*load.Package {
	out := map[string]*load.Package{}
	for path, src := range knownStd {
		af, err := parser.ParseFile(fset, "(gnark) "+path+"/known.go", src, parser.SkipObjectResolution)
		if err != nil {
			panic("knownStd " + path + ": " + err.Error())
		}
		p := &load.Package{PkgPath: path, Name: af.Name.Name}
		f := &load.File{Abs: "(gnark) " + path, Rel: "(gnark) " + path, AST: af, Pkg: p, Imports: map[string]string{}}
		for _, imp := range af.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			f.Imports[lastElem(ip)] = ip
		}
		p.Files = []*load.File{f}
		out[path] = p
	}
	return out
}

type syntaxWalker struct {
	prog *load.Program
	l    *layout
	// byPath maps an import path to a loaded package (for cross-package
	// lookups inside the target repository).
	byPath map[string]*load.Package
	known  map[string]*load.Package
}

func newSyntaxWalker(prog *load.Program, l *layout, f *load.File) *syntaxWalker {
	sw := &syntaxWalker{prog: prog, l: l, byPath: map[string]*load.Package{}, known: knownPackages(prog.Fset)}
	for _, p := range prog.Packages {
		if p.PkgPath != "" {
			sw.byPath[p.PkgPath] = p
		}
	}
	return sw
}

func (sw *syntaxWalker) lookupLocal(p *load.Package, name string) (*ast.TypeSpec, *load.File) {
	files := p.Files
	// syntax-mode packages are grouped per directory+name; test packages may
	// split, so also search sibling packages in the same directory.
	for _, q := range sw.prog.Packages {
		if q != p && q.Dir == p.Dir && strings.TrimSuffix(q.Name, "_test") == strings.TrimSuffix(p.Name, "_test") {
			files = append(files, q.Files...)
		}
	}
	for _, f := range files {
		for _, d := range f.AST.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				if ts.Name.Name == name {
					return ts, f
				}
			}
		}
	}
	return nil, nil
}

func (sw *syntaxWalker) resolveSel(f *load.File, sel *ast.SelectorExpr) (*ast.TypeSpec, *load.File, string) {
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, nil, ""
	}
	path := f.Imports[id.Name]
	if path == "" {
		return nil, nil, ""
	}
	if p := sw.known[path]; p != nil {
		ts, tf := sw.lookupLocal(p, sel.Sel.Name)
		return ts, tf, path
	}
	if p := sw.byPath[path]; p != nil {
		ts, tf := sw.lookupLocal(p, sel.Sel.Name)
		return ts, tf, path
	}
	// syntax-only packages have no PkgPath; match on directory suffix
	for _, p := range sw.prog.Packages {
		if p.PkgPath == "" && p.Dir != "" && strings.HasSuffix(p.Dir, "/"+lastElem(path)) && p.Name == lastElem(path) {
			ts, tf := sw.lookupLocal(p, sel.Sel.Name)
			if ts != nil {
				return ts, tf, path
			}
		}
	}
	return nil, nil, path
}

func (sw *syntaxWalker) isVariable(f *load.File, e ast.Expr) bool {
	return isPkgSel(f, e, pkgFrontend, "Variable")
}

func stripIndex(e ast.Expr) ast.Expr {
	switch x := e.(type) {
	case *ast.IndexExpr:
		return x.X
	case *ast.IndexListExpr:
		return x.X
	case *ast.ParenExpr:
		return stripIndex(x.X)
	}
	return e
}

// leaves returns the static leaf count of e, or -1 if dynamic / unknown.
func (sw *syntaxWalker) leaves(f *load.File, e ast.Expr, depth int) int {
	if depth > 24 {
		return -1
	}
	if sw.isVariable(f, e) {
		return 1
	}
	switch x := stripIndex(e).(type) {
	case *ast.StarExpr:
		return sw.leaves(f, x.X, depth+1)
	case *ast.ArrayType:
		c := sw.leaves(f, x.Elt, depth+1)
		if x.Len == nil {
			if c == 0 {
				return 0
			}
			return -1
		}
		n, ok := constInt(f, f.Pkg.Files, x.Len)
		if !ok || c < 0 {
			return -1
		}
		return n * c
	case *ast.StructType:
		n := 0
		for _, fld := range x.Fields.List {
			if fld.Tag != nil && parseGnarkTag(unquoteTag(fld.Tag.Value)).omit {
				continue
			}
			c := sw.leaves(f, fld.Type, depth+1)
			if c < 0 {
				return -1
			}
			cnt := len(fld.Names)
			if cnt == 0 {
				cnt = 1
			}
			n += c * cnt
		}
		return n
	case *ast.Ident:
		if ts, tf := sw.lookupLocal(f.Pkg, x.Name); ts != nil {
			return sw.leaves(tf, ts.Type, depth+1)
		}
		return 0
	case *ast.SelectorExpr:
		ts, tf, path := sw.resolveSel(f, x)
		if ts != nil {
			return sw.leaves(tf, ts.Type, depth+1)
		}
		if opaqueImport(path) {
			return -1
		}
		return 0
	}
	return 0
}

// opaqueImport reports whether an unresolved type from path may hold witness
// leaves: gnark std and third-party modules may, the standard library and
// non-std gnark packages (frontend, backend, constraint) do not.
func opaqueImport(path string) bool {
	if path == "" {
		return false
	}
	if isGnarkPath(path) {
		return strings.HasPrefix(path, gnarkRoot+"/std")
	}
	first := strings.SplitN(path, "/", 2)[0]
	return strings.Contains(first, ".")
}

func unquoteTag(s string) string {
	u, err := strconv.Unquote(s)
	if err != nil {
		return strings.Trim(s, "`")
	}
	return u
}

var builtinTypes = map[string]bool{
	"bool": true, "string": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"byte": true, "rune": true, "float32": true, "float64": true, "complex64": true, "complex128": true,
	"error": true, "any": true,
}

func (sw *syntaxWalker) walkType(f *load.File, e ast.Expr, goPath, name, vis string, depth int) {
	l := sw.l
	if depth > 24 {
		l.note("type nesting deeper than 24 at %s; layout truncated", goPath)
		l.w.Resolved = false
		return
	}
	if sw.isVariable(f, e) {
		l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: "frontend.Variable", Kind: "variable", Len: 1, Decl: sw.pos(f, e)})
		return
	}
	switch x := stripIndex(e).(type) {
	case *ast.StarExpr:
		m := l.mark()
		sw.walkType(f, x.X, goPath, name, vis, depth+1)
		l.notePointer(m, goPath)
	case *ast.StructType:
		sw.walkStruct(f, x, goPath, name, vis, depth)
	case *ast.ArrayType:
		elemVar := sw.isVariable(f, x.Elt)
		k := sw.leaves(f, x.Elt, 0)
		if x.Len == nil { // slice
			if k == 0 {
				return
			}
			if elemVar {
				l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: exprString(sw.prog.Fset, e), Kind: "slice", Len: -1, Decl: sw.pos(f, e),
					Note: "length fixed by the slice assigned before Compile; an empty slice is ignored with a warning"})
				return
			}
			l.add(leafVis(vis), &Group{Name: name + "_{i}", GoPath: goPath + "[i]", Type: exprString(sw.prog.Fset, e), Kind: "slice", Len: -1, PerElem: max(k, 0), Decl: sw.pos(f, e),
				Note: fmt.Sprintf("slice of %s, %s leaves per element, element-major order", exprString(sw.prog.Fset, x.Elt), countStr(k))})
			return
		}
		n, ok := constInt(f, f.Pkg.Files, x.Len)
		if !ok {
			l.w.Resolved = false
			if k != 0 {
				l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: exprString(sw.prog.Fset, e), Kind: "array", Len: -1, Decl: sw.pos(f, e),
					Note: "array length " + exprString(sw.prog.Fset, x.Len) + " did not evaluate without type information"})
			}
			return
		}
		if elemVar {
			l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: exprString(sw.prog.Fset, e), Kind: "array", Len: n, Decl: sw.pos(f, e)})
			return
		}
		if k == 0 {
			return
		}
		if k > 0 && n*k > maxExpand {
			l.add(leafVis(vis), &Group{Name: name + "_{i}", GoPath: goPath + "[i]", Type: exprString(sw.prog.Fset, e), Kind: "array", Len: n * k, Decl: sw.pos(f, e),
				Note: fmt.Sprintf("%d elements x %d leaves, element-major order", n, k)})
			return
		}
		for i := 0; i < n; i++ {
			sw.walkType(f, x.Elt, fmt.Sprintf("%s[%d]", goPath, i), joinName(name, strconv.Itoa(i)), vis, depth+1)
		}
	case *ast.Ident:
		if builtinTypes[x.Name] {
			return
		}
		ts, tf := sw.lookupLocal(f.Pkg, x.Name)
		if ts == nil {
			// a type parameter or an unknown name
			return
		}
		sw.walkType(tf, ts.Type, goPath, name, vis, depth+1)
	case *ast.SelectorExpr:
		ts, tf, path := sw.resolveSel(f, x)
		if ts == nil {
			if !opaqueImport(path) {
				return // standard library or gnark frontend/backend types: no leaves
			}
			l.w.Resolved = false
			l.add(leafVis(vis), &Group{Name: name, GoPath: goPath, Type: exprString(sw.prog.Fset, e), Kind: "opaque", Len: -1, Decl: sw.pos(f, e),
				Note: "type from " + path + " not resolvable without type information (run without --syntax-only after `go mod download`)"})
			return
		}
		m := l.mark()
		sw.walkType(tf, ts.Type, goPath, name, vis, depth+1)
		if path == pkgEmulated && x.Sel.Name == "Element" {
			l.noteLimbs(m)
		}
	case *ast.InterfaceType:
		l.note("interface field %s: walked through its dynamic value at compile time; nil contributes no leaves", goPath)
	}
}

func (sw *syntaxWalker) walkStruct(f *load.File, st *ast.StructType, goPath, name, vis string, depth int) {
	l := sw.l
	for _, fld := range st.Fields.List {
		ti := tagInfo{}
		if fld.Tag != nil {
			ti = parseGnarkTag(unquoteTag(fld.Tag.Value))
		}
		if len(fld.Names) == 0 { // embedded
			fpath := joinPath(goPath, recvTypeName(fld.Type))
			if ti.omit {
				continue
			}
			if ti.present {
				l.note("embedded field %s has a gnark tag; frontend/schema ignores tags on embedded fields, so its leaves keep the parent's visibility (%s)", fpath, leafVis(vis))
			}
			m := l.mark()
			sw.walkType(f, fld.Type, fpath, name, vis, depth+1)
			l.attribute(m, sw.pos(f, fld.Type), depth == 0)
			continue
		}
		for _, n := range fld.Names {
			fpath := joinPath(goPath, n.Name)
			if ti.omit {
				if inRepo(sw.pos(f, n)) && sw.leaves(f, fld.Type, 0) != 0 {
					l.w.Omit = append(l.w.Omit, &Omitted{GoPath: fpath, Type: exprString(sw.prog.Fset, fld.Type), Decl: sw.pos(f, n)})
				}
				continue
			}
			nm := n.Name
			if ti.name != "" {
				nm = ti.name
			}
			cv := childVisibility(l, vis, ti, fpath)
			if sel, ok := stripIndex(fld.Type).(*ast.SelectorExpr); ok && sel.Sel.Name == "VerifyingKey" &&
				(isPkgSel(f, sel, pkgRecG16, "VerifyingKey") || isPkgSel(f, sel, pkgRecPlonk, "VerifyingKey")) {
				l.w.VKAt = append(l.w.VKAt, sw.pos(f, n))
				l.note("field %s is a recursion VerifyingKey: the inner VK is part of the witness", fpath)
			}
			if !n.IsExported() && sw.leaves(f, fld.Type, 0) != 0 {
				l.note("unexported field %s holds witness leaves; frontend.Compile cannot set it (\"can't set val\")", fpath)
			}
			m := l.mark()
			sw.walkType(f, fld.Type, fpath, joinName(name, nm), cv, depth+1)
			l.attribute(m, sw.pos(f, n), depth == 0)
		}
	}
}

func (sw *syntaxWalker) pos(f *load.File, n ast.Node) Pos {
	if strings.HasPrefix(f.Rel, "(gnark)") {
		return Pos{File: f.Rel}
	}
	p := sw.prog.Fset.Position(n.Pos())
	return Pos{File: f.Rel, Line: p.Line}
}
