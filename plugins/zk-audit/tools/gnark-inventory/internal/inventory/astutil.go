package inventory

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
)

const (
	gnarkRoot   = "github.com/consensys/gnark"
	pkgFrontend = gnarkRoot + "/frontend"
	pkgBits     = gnarkRoot + "/std/math/bits"
	pkgBitslice = gnarkRoot + "/std/math/bitslice"
	pkgCmp      = gnarkRoot + "/std/math/cmp"
	pkgEmulated = gnarkRoot + "/std/math/emulated"
	pkgSelector = gnarkRoot + "/std/selector"
	pkgGroth16  = gnarkRoot + "/backend/groth16"
	pkgPlonk    = gnarkRoot + "/backend/plonk"
	pkgBackend  = gnarkRoot + "/backend"
	pkgSolidity = gnarkRoot + "/backend/solidity"
	pkgUnsafeKZ = gnarkRoot + "/test/unsafekzg"
	pkgSolver   = gnarkRoot + "/constraint/solver"
	pkgMulti    = gnarkRoot + "/std/multicommit"
	pkgRecG16   = gnarkRoot + "/std/recursion/groth16"
	pkgRecPlonk = gnarkRoot + "/std/recursion/plonk"
	pkgPedersen = gnarkRoot + "/std/commitments/pedersen"
	pkgMiMC     = gnarkRoot + "/std/hash/mimc"
	pkgMerkle   = gnarkRoot + "/std/accumulator/merkle"
	pkgEdDSA    = gnarkRoot + "/std/signature/eddsa"
	pkgECDSA    = gnarkRoot + "/std/signature/ecdsa"
	pkgWitness  = gnarkRoot + "/backend/witness"
)

func isGnarkPath(p string) bool { return p == gnarkRoot || strings.HasPrefix(p, gnarkRoot+"/") }

// importsGnark reports whether the file imports any gnark package.
func importsGnark(f *load.File) bool {
	for _, p := range f.Imports {
		if isGnarkPath(p) {
			return true
		}
	}
	return false
}

func importsPath(f *load.File, path string) bool {
	for _, p := range f.Imports {
		if p == path {
			return true
		}
	}
	return false
}

// isPkgSel reports whether e is `<alias>.<name>` with alias importing path.
func isPkgSel(f *load.File, e ast.Expr, path, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return f.Imports[id.Name] == path && sel.Sel.Name == name
}

// isNamed reports whether t is the named type path.name (through pointers).
func isNamed(t types.Type, path, name string) bool {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	var obj *types.TypeName
	switch n := t.(type) {
	case *types.Named:
		obj = n.Obj()
	case *types.Alias:
		obj = n.Obj()
	default:
		return false
	}
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == path && obj.Name() == name
}

func namedIn(t types.Type, pathPrefix string) (string, string, bool) {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return "", "", false
	}
	if strings.HasPrefix(n.Obj().Pkg().Path(), pathPrefix) {
		return n.Obj().Pkg().Path(), n.Obj().Name(), true
	}
	return "", "", false
}

// callee describes the function a call expression invokes.
type callee struct {
	// Pkg is the import path when the call is package-qualified (pkg.F).
	Pkg  string
	Name string
	// Recv is the receiver expression for method calls.
	Recv ast.Expr
}

func calleeOf(f *load.File, call *ast.CallExpr) callee {
	fun := call.Fun
	// strip generic instantiation: F[T](...)
	switch x := fun.(type) {
	case *ast.IndexExpr:
		fun = x.X
	case *ast.IndexListExpr:
		fun = x.X
	}
	switch x := fun.(type) {
	case *ast.Ident:
		return callee{Name: x.Name}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if p, ok := f.Imports[id.Name]; ok && !shadowedImport(f, id) {
				return callee{Pkg: p, Name: x.Sel.Name}
			}
		}
		return callee{Name: x.Sel.Name, Recv: x.X}
	}
	return callee{}
}

// shadowedImport reports whether id refers to a local object instead of the
// import of the same name (types mode only; syntax mode assumes the import).
func shadowedImport(f *load.File, id *ast.Ident) bool {
	if f.Pkg.Info == nil {
		return false
	}
	if obj := f.Pkg.Info.Uses[id]; obj != nil {
		_, isPkg := obj.(*types.PkgName)
		return !isPkg
	}
	return false
}

func exprString(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, n); err != nil {
		return ""
	}
	s := strings.Join(strings.Fields(b.String()), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func intLit(e ast.Expr) (int, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.ParseInt(bl.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// constInt evaluates e as an integer constant, using type information when
// available and a small same-package evaluator otherwise.
func constInt(f *load.File, pkgFiles []*load.File, e ast.Expr) (int, bool) {
	if f.Pkg.Info != nil {
		if tv, ok := f.Pkg.Info.Types[e]; ok && tv.Value != nil {
			if v, ok := constantInt(tv.Value.ExactString()); ok {
				return v, true
			}
		}
	}
	return evalConst(pkgFiles, e, 0)
}

func constantInt(s string) (int, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return int(n), err == nil
}

func evalConst(files []*load.File, e ast.Expr, depth int) (int, bool) {
	if depth > 16 {
		return 0, false
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		return intLit(x)
	case *ast.ParenExpr:
		return evalConst(files, x.X, depth+1)
	case *ast.Ident:
		if v := findConst(files, x.Name); v != nil {
			return evalConst(files, v, depth+1)
		}
	case *ast.BinaryExpr:
		a, ok1 := evalConst(files, x.X, depth+1)
		b, ok2 := evalConst(files, x.Y, depth+1)
		if !ok1 || !ok2 {
			return 0, false
		}
		switch x.Op {
		case token.ADD:
			return a + b, true
		case token.SUB:
			return a - b, true
		case token.MUL:
			return a * b, true
		case token.QUO:
			if b != 0 {
				return a / b, true
			}
		case token.SHL:
			if b >= 0 && b < 62 {
				return a << uint(b), true
			}
		}
	}
	return 0, false
}

func findConst(files []*load.File, name string) ast.Expr {
	for _, f := range files {
		for _, d := range f.AST.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if n.Name == name && i < len(vs.Values) {
						return vs.Values[i]
					}
				}
			}
		}
	}
	return nil
}

// funcScope describes the function enclosing a node.
type funcScope struct {
	Decl     *ast.FuncDecl
	Name     string
	RecvType string
	RecvName string
	// APINames are parameter names of type frontend.API.
	APINames map[string]bool
	// Circuit is the circuit name when RecvType is a circuit.
	Circuit string
}

func (s *funcScope) inCircuitCode() bool {
	return s != nil && (len(s.APINames) > 0 || s.Circuit != "")
}

func newFuncScope(f *load.File, fd *ast.FuncDecl) *funcScope {
	s := &funcScope{Decl: fd, Name: fd.Name.Name, APINames: map[string]bool{}}
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		r := fd.Recv.List[0]
		s.RecvType = recvTypeName(r.Type)
		if len(r.Names) > 0 {
			s.RecvName = r.Names[0].Name
		}
		s.Name = s.RecvType + "." + fd.Name.Name
	}
	addAPIParams(f, fd.Type, s.APINames)
	return s
}

func addAPIParams(f *load.File, ft *ast.FuncType, into map[string]bool) {
	if ft.Params == nil {
		return
	}
	for _, p := range ft.Params.List {
		if isAPIType(f, p.Type) {
			for _, n := range p.Names {
				into[n.Name] = true
			}
		}
	}
}

func isAPIType(f *load.File, e ast.Expr) bool {
	if isPkgSel(f, e, pkgFrontend, "API") {
		return true
	}
	if f.Pkg.Info != nil {
		if t := f.Pkg.Info.TypeOf(e); t != nil {
			return isNamed(t, pkgFrontend, "API")
		}
	}
	return false
}

func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvTypeName(x.X)
	case *ast.IndexListExpr:
		return recvTypeName(x.X)
	}
	return ""
}

// apiLike reports whether e is a frontend.API value in scope s.
func apiLike(f *load.File, s *funcScope, e ast.Expr) bool {
	if f.Pkg.Typed && f.Pkg.Info != nil {
		if t := f.Pkg.Info.TypeOf(e); t != nil {
			return isNamed(t, pkgFrontend, "API") || isNamed(t, pkgFrontend, "Builder") ||
				strings.Contains(types.TypeString(t, nil), pkgFrontend+".API")
		}
	}
	switch x := e.(type) {
	case *ast.Ident:
		return s != nil && s.APINames[x.Name]
	case *ast.SelectorExpr:
		n := strings.ToLower(x.Sel.Name)
		return n == "api"
	}
	return false
}

// isVariableExpr reports whether e has type frontend.Variable (types mode).
func isVariableExpr(f *load.File, e ast.Expr) bool {
	if f.Pkg.Info == nil {
		return false
	}
	t := f.Pkg.Info.TypeOf(e)
	return t != nil && isNamed(t, pkgFrontend, "Variable")
}
