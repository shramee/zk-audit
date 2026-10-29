package detect

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
)

const (
	pkgFrontend = gnarkModule + "/frontend"
	pkgEmulated = gnarkModule + "/std/math/emulated"
)

// libScan counts exported gadgets and production circuits by syntax only.
type libScan struct {
	gadgets  int
	circuits int
	pkgs     set
}

// scan parses one Go file that imports gnark's frontend or emulated
// packages and counts its exported gadgets and non-test Define methods.
func (l *libScan) scan(f fsutil.File, src []byte, imports *ast.File) {
	if strings.HasSuffix(f.Rel, "_test.go") || imports.Name.Name == "main" {
		return
	}
	alias := map[string]string{}
	for _, imp := range imports.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if p != pkgFrontend && p != pkgEmulated {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		alias[name] = p
	}
	if len(alias) == 0 {
		return
	}
	af, err := parser.ParseFile(token.NewFileSet(), f.Abs, src, parser.SkipObjectResolution)
	if err != nil || af == nil {
		return
	}
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || !takesGadgetParam(fd.Type, alias) {
			continue
		}
		if fd.Name.Name == "Define" && fd.Recv != nil {
			l.circuits++
			continue
		}
		if !fd.Name.IsExported() || (fd.Recv != nil && !recvExported(fd.Recv)) {
			continue
		}
		l.gadgets++
		l.pkgs[path.Dir(f.Rel)] = true
	}
}

// takesGadgetParam reports whether a parameter is frontend.API or
// (*)emulated.Field[...].
func takesGadgetParam(ft *ast.FuncType, alias map[string]string) bool {
	if ft.Params == nil {
		return false
	}
	for _, p := range ft.Params.List {
		t := p.Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		switch x := t.(type) {
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		}
		sel, ok := t.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			continue
		}
		switch alias[id.Name] {
		case pkgFrontend:
			if sel.Sel.Name == "API" {
				return true
			}
		case pkgEmulated:
			if sel.Sel.Name == "Field" {
				return true
			}
		}
	}
	return false
}

func recvExported(fl *ast.FieldList) bool {
	if len(fl.List) == 0 {
		return false
	}
	t := fl.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.IsExported()
		}
		return false
	}
}

// library decides library mode.
func (st *Stack) library() {
	l := &st.Library
	nv := len(st.Solidity.Verifiers)
	switch {
	case l.Gadgets == 0:
		l.Reason = "no exported gadget (exported function or method taking frontend.API or *emulated.Field)"
	case l.ProductionCircuits > 0:
		l.Reason = fmt.Sprintf("%d exported gadgets, but %d production circuits (non-test Define): audit the circuits; L1 checks the gadgets in deep", l.Gadgets, l.ProductionCircuits)
	case nv > 0:
		l.Reason = fmt.Sprintf("%d exported gadgets, but %d verifier contracts: audit the integration", l.Gadgets, nv)
	default:
		l.Mode = true
		l.Reason = fmt.Sprintf("%d exported gadgets in %d packages, no production circuit and no verifier contract", l.Gadgets, len(l.Packages))
	}
}

var reCacheVersion = regexp.MustCompile(`@(v\d+\.\d+\.\d+[^/\\]*)$`)

// selfVersion returns the version of a gnark checkout in the module cache
// (…/gnark@v0.14.0/go.mod), or "".
func selfVersion(gomodAbs string) string {
	if m := reCacheVersion.FindStringSubmatch(filepath.Dir(gomodAbs)); m != nil {
		return m[1]
	}
	return ""
}
