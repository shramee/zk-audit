// Package load loads the Go sources of a target repository. It prefers
// golang.org/x/tools/go/packages with full type information and falls back to
// go/parser for every file it could not load that way.
package load

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
)

// Options control loading.
type Options struct {
	// SyntaxOnly skips go/packages entirely.
	SyntaxOnly bool
	// AllowNetwork lets the go command download modules. When false the
	// loader sets GOPROXY=off so an audit never touches the network.
	AllowNetwork bool
}

// Package is one loaded package (or, in syntax mode, one directory+name).
type Package struct {
	ID      string
	PkgPath string
	Name    string
	Dir     string
	Types   *types.Package
	Info    *types.Info
	Files   []*File
	Errors  []string
	// Typed is true when type information is complete and reliable.
	Typed bool
}

// File is one Go source file, analysed exactly once.
type File struct {
	Abs    string
	Rel    string
	AST    *ast.File
	Pkg    *Package
	IsTest bool
	// Imports maps the local name of each import to its path.
	Imports map[string]string
}

// Program is the loaded repository.
type Program struct {
	Root     string
	Fset     *token.FileSet
	Packages []*Package
	Files    []*File
	// Mode is "types", "syntax" or "mixed".
	Mode   string
	Errors []string
}

// Load loads every Go file under root.
func Load(root string, opt Options) (*Program, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	prog := &Program{Root: root, Fset: token.NewFileSet()}
	seen := map[string]bool{}

	if !opt.SyntaxOnly {
		mods, err := fsutil.Walk(root, func(rel string) bool { return filepath.Base(rel) == "go.mod" })
		if err != nil {
			return nil, err
		}
		for _, m := range mods {
			prog.loadTyped(filepath.Dir(m.Abs), opt, seen)
		}
	}

	// Everything not covered by a typed load is parsed syntax-only.
	gofiles, err := fsutil.Walk(root, fsutil.HasExt(".go"))
	if err != nil {
		return nil, err
	}
	synth := map[string]*Package{}
	for _, f := range gofiles {
		if seen[f.Abs] {
			continue
		}
		af, perr := parser.ParseFile(prog.Fset, f.Abs, nil, parser.ParseComments|parser.SkipObjectResolution)
		if af == nil {
			prog.Errors = append(prog.Errors, fmt.Sprintf("%s: %v", f.Rel, perr))
			continue
		}
		key := filepath.Dir(f.Abs) + "|" + af.Name.Name
		p := synth[key]
		if p == nil {
			p = &Package{ID: "syntax:" + key, Name: af.Name.Name, Dir: filepath.Dir(f.Abs)}
			synth[key] = p
			prog.Packages = append(prog.Packages, p)
		}
		if perr != nil {
			p.Errors = append(p.Errors, perr.Error())
		}
		file := prog.newFile(f.Abs, af, p)
		p.Files = append(p.Files, file)
		seen[f.Abs] = true
	}

	typed, untyped := 0, 0
	for _, f := range prog.Files {
		if f.Pkg.Typed {
			typed++
		} else {
			untyped++
		}
	}
	switch {
	case untyped == 0 && typed > 0:
		prog.Mode = "types"
	case typed == 0:
		prog.Mode = "syntax"
	default:
		prog.Mode = "mixed"
	}
	sort.Slice(prog.Files, func(i, j int) bool { return prog.Files[i].Rel < prog.Files[j].Rel })
	return prog, nil
}

func (prog *Program) newFile(abs string, af *ast.File, p *Package) *File {
	rel, err := filepath.Rel(prog.Root, abs)
	if err != nil {
		rel = abs
	}
	f := &File{
		Abs: abs, Rel: filepath.ToSlash(rel), AST: af, Pkg: p,
		IsTest:  strings.HasSuffix(abs, "_test.go"),
		Imports: importMap(af),
	}
	prog.Files = append(prog.Files, f)
	return f
}

func importMap(af *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range af.Imports {
		path := strings.Trim(imp.Path.Value, "\"`")
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			name = defaultImportName(path)
		}
		if name == "_" || name == "." {
			continue
		}
		m[name] = path
	}
	return m
}

// defaultImportName guesses the package name of an import path: the last
// element, ignoring a major-version suffix and replacing '-' with '_'.
func defaultImportName(path string) string {
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	if len(parts) > 1 && len(last) >= 2 && last[0] == 'v' && isDigits(last[1:]) {
		last = parts[len(parts)-2]
	}
	last = strings.TrimPrefix(last, "go-")
	return strings.ReplaceAll(last, "-", "_")
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func (prog *Program) loadTyped(dir string, opt Options, seen map[string]bool) {
	env := targetEnv(os.Environ(), opt.AllowNetwork)
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Dir:   dir,
		Env:   env,
		Fset:  prog.Fset,
		Tests: true,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parser.ParseComments)
		},
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		rel, _ := filepath.Rel(prog.Root, dir)
		prog.Errors = append(prog.Errors, fmt.Sprintf("go/packages in %s: %v", filepath.ToSlash(rel), firstLine(err.Error())))
		return
	}
	// plain packages first, then test variants, so a non-test file is
	// analysed with its plain package's type information.
	sort.SliceStable(pkgs, func(i, j int) bool { return variantRank(pkgs[i].ID) < variantRank(pkgs[j].ID) })
	for _, lp := range pkgs {
		if strings.HasSuffix(lp.ID, ".test") && lp.Name == "main" {
			continue // generated test main
		}
		p := &Package{ID: lp.ID, PkgPath: lp.PkgPath, Name: lp.Name, Types: lp.Types, Info: lp.TypesInfo}
		for _, e := range lp.Errors {
			p.Errors = append(p.Errors, firstLine(e.Error()))
		}
		p.Typed = len(p.Errors) == 0 && lp.TypesInfo != nil && lp.Types != nil && !lp.IllTyped
		added := false
		for i, af := range lp.Syntax {
			abs := ""
			if i < len(lp.CompiledGoFiles) {
				abs = lp.CompiledGoFiles[i]
			} else {
				abs = prog.Fset.Position(af.Package).Filename
			}
			if !strings.HasSuffix(abs, ".go") || seen[abs] || !strings.HasPrefix(abs, prog.Root+string(filepath.Separator)) {
				continue
			}
			if p.Dir == "" {
				p.Dir = filepath.Dir(abs)
			}
			p.Files = append(p.Files, prog.newFile(abs, af, p))
			seen[abs] = true
			added = true
		}
		if added {
			prog.Packages = append(prog.Packages, p)
			for _, e := range p.Errors {
				prog.Errors = append(prog.Errors, fmt.Sprintf("%s: %s", lp.PkgPath, e))
			}
		}
	}
}

// targetEnv prepares the go command environment for loading the target: it
// drops any -mod flag inherited from the caller (the target decides between
// its vendor directory and the module cache) and, unless network access is
// allowed, sets GOPROXY=off so loading never downloads modules.
func targetEnv(environ []string, allowNetwork bool) []string {
	var env []string
	for _, kv := range environ {
		if strings.HasPrefix(kv, "GOFLAGS=") {
			var keep []string
			for _, f := range strings.Fields(strings.TrimPrefix(kv, "GOFLAGS=")) {
				if !strings.HasPrefix(f, "-mod=") {
					keep = append(keep, f)
				}
			}
			kv = "GOFLAGS=" + strings.Join(keep, " ")
		}
		if !allowNetwork && strings.HasPrefix(kv, "GOPROXY=") {
			continue
		}
		env = append(env, kv)
	}
	if !allowNetwork {
		env = append(env, "GOPROXY=off")
	}
	return env
}

func variantRank(id string) int {
	switch {
	case strings.Contains(id, "_test ["), strings.HasSuffix(id, "_test"):
		return 2
	case strings.Contains(id, " ["):
		return 1
	}
	return 0
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Pos returns the file-relative position of n.
func (prog *Program) Pos(f *File, n ast.Node) (string, int) {
	p := prog.Fset.Position(n.Pos())
	return f.Rel, p.Line
}
