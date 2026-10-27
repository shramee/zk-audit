package inventory

import (
	"fmt"
	"go/ast"
	"path"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/solidity"
)

// SchemaVersion of inventory.json.
const SchemaVersion = "1"

// Options for Build.
type Options struct {
	ToolVersion string
	// Files restricts reported items to these repo-relative files or
	// directories. Type resolution still uses the whole repository.
	Files []string
}

// Build produces the inventory of a loaded program.
func Build(prog *load.Program, opt Options) (*Inventory, error) {
	inv := &Inventory{
		SchemaVersion: SchemaVersion, ToolVersion: opt.ToolVersion, Repo: prog.Root,
		LoadMode: prog.Mode, LoadErrors: append([]string{}, prog.Errors...), Scope: opt.Files,
		Circuits: []*Circuit{}, Hints: []*HintSite{}, HintFuncs: []*HintFunc{}, Footguns: []*Footgun{},
	}
	if len(inv.LoadErrors) > 50 {
		n := len(inv.LoadErrors)
		inv.LoadErrors = append(inv.LoadErrors[:50], fmt.Sprintf("... %d more", n-50))
	}
	inScope := func(rel string) bool { return fsutil.InScope(rel, opt.Files) }

	// circuits
	all := findCircuits(prog)
	byKey := map[string]*Circuit{}
	for _, c := range all {
		for _, f := range prog.Files {
			if f.Rel == c.Define.File {
				byKey[scopeKey(f, c.Name)] = c
			}
		}
		if inScope(c.Define.File) || inScope(c.Decl.File) {
			inv.Circuits = append(inv.Circuits, c)
		}
	}

	// hints and footguns
	hintN := 0
	nextHint := func() string { hintN++; return fmt.Sprintf("H%d", hintN) }
	registered := map[string]bool{}
	var funcs []*HintFunc
	for _, f := range prog.Files {
		inv.Summary.GoFiles++
		if inScope(f.Rel) {
			// hint functions often live in files that only import math/big
			funcs = append(funcs, hintFuncs(prog, f)...)
		}
		if !importsGnark(f) {
			continue
		}
		inv.Summary.GnarkFiles++
		for k := range registeredHints(prog, f) {
			registered[k] = true
		}
		if !inScope(f.Rel) {
			continue
		}
		for _, d := range f.AST.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			sc := newFuncScope(f, fd)
			if c, ok := byKey[scopeKey(f, sc.RecvType)]; ok {
				sc.Circuit = c.Name
			}
			inv.Hints = append(inv.Hints, analyzeHints(prog, f, sc, fd.Body, nextHint)...)
		}
		scanFootguns(prog, f, byKey, &inv.Footguns)
	}
	// hint functions: registration and call-site counts
	for _, h := range funcs {
		h.Registered = registered[h.Name]
		for _, s := range inv.Hints {
			if s.HintFunc == h.Name || strings.HasSuffix(s.HintFunc, "."+h.Name) {
				h.CallSites++
				if s.HintDecl == nil {
					p := h.Pos
					s.HintDecl = &p
				}
			}
		}
	}
	inv.HintFuncs = append(inv.HintFuncs, funcs...)

	// derived footguns
	witnessFootguns(prog, inv.Circuits, &inv.Footguns)
	for _, s := range inv.Hints {
		switch s.Status {
		case "unreached", "partially_unreached":
			var idx []string
			for _, o := range s.Outputs {
				switch o.Status {
				case "unreached":
					idx = append(idx, o.Index)
				case "unknown":
					idx = append(idx, "any beyond those used (count "+s.NbOutputs+")")
				}
			}
			inv.Footguns = append(inv.Footguns, &Footgun{ID: "FG-HINT-UNREACHED", Pos: s.Pos, Function: s.Function, Circuit: s.Circuit,
				Snippet: s.Call + "(" + s.HintFunc + ", " + s.NbOutputs + ", ...)",
				Note:    fmt.Sprintf("%s outputs %s reach no constraint here. %s", s.ID, strings.Join(idx, ","), ruleNote("FG-HINT-UNREACHED")), InTest: s.InTest})
		case "escapes":
			var via []string
			for _, o := range s.Outputs {
				for _, e := range o.Escapes {
					via = appendUniq(via, e)
				}
			}
			inv.Footguns = append(inv.Footguns, &Footgun{ID: "FG-HINT-ESCAPES", Pos: s.Pos, Function: s.Function, Circuit: s.Circuit,
				Snippet: s.Call + "(" + s.HintFunc + ", " + s.NbOutputs + ", ...)",
				Note:    fmt.Sprintf("%s outputs escape via %s. %s", s.ID, strings.Join(via, ", "), ruleNote("FG-HINT-ESCAPES")), InTest: s.InTest})
		}
	}
	inv.Footguns = sortFootguns(inv.Footguns)
	inv.Summary.Footguns = map[string]int{}
	for i, fg := range inv.Footguns {
		fg.Key = fmt.Sprintf("F%d", i+1)
		if !fg.InTest {
			inv.Summary.Footguns[fg.ID]++
		}
	}
	// link to circuits
	// circuits are identified by package directory and type name: several
	// packages may each define a type called Circuit
	for _, c := range inv.Circuits {
		dir := path.Dir(c.Define.File)
		for _, s := range inv.Hints {
			if s.Circuit == c.Name && path.Dir(s.Pos.File) == dir {
				c.HintIDs = append(c.HintIDs, s.ID)
			}
		}
		for _, fg := range inv.Footguns {
			if fg.Circuit == c.Name && path.Dir(fg.Pos.File) == dir {
				c.FootgunIDs = append(c.FootgunIDs, fg.Key)
			}
		}
	}

	// Solidity
	sol, err := scanSolidity(prog.Root, opt.Files)
	if err != nil {
		return nil, err
	}
	inv.Contracts = sol

	// summary
	inv.Summary.Circuits = len(inv.Circuits)
	for _, c := range inv.Circuits {
		if c.Witness.NbPublic > 0 && !c.InTest {
			inv.Summary.PublicInputs += c.Witness.NbPublic
		}
	}
	inv.Summary.HintSites = len(inv.Hints)
	for _, s := range inv.Hints {
		for _, o := range s.Outputs {
			if o.Status == "unreached" && !s.InTest {
				inv.Summary.UnreachedHints++
			}
		}
	}
	inv.Summary.SolidityFiles = len(sol.Files)
	inv.Summary.VerifyCalls = len(sol.VerifyCalls)
	return inv, nil
}

func sortFootguns(fs []*Footgun) []*Footgun {
	order := map[string]int{}
	for i, r := range Rules {
		order[r.ID] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Pos.File != b.Pos.File {
			return a.Pos.File < b.Pos.File
		}
		if a.Pos.Line != b.Pos.Line {
			return a.Pos.Line < b.Pos.Line
		}
		return order[a.ID] < order[b.ID]
	})
	// drop exact duplicates (same rule, same line)
	seen := map[string]bool{}
	j := 0
	for _, f := range fs {
		k := fmt.Sprintf("%s|%s|%d", f.ID, f.Pos.File, f.Pos.Line)
		if seen[k] {
			continue
		}
		seen[k] = true
		fs[j] = f
		j++
	}
	return fs[:j]
}

// scanSolidity scans .sol files, skipping Foundry dependency trees (lib/ next
// to a foundry.toml) and test / script files.
func scanSolidity(root string, files []string) (*solidity.Result, error) {
	tomls, err := fsutil.Walk(root, func(rel string) bool { return path.Base(rel) == "foundry.toml" })
	if err != nil {
		return nil, err
	}
	var libs []string
	for _, t := range tomls {
		d := path.Dir(t.Rel)
		if d == "." {
			libs = append(libs, "lib/")
		} else {
			libs = append(libs, d+"/lib/")
		}
	}
	sols, err := fsutil.Walk(root, func(rel string) bool {
		if !strings.HasSuffix(rel, ".sol") || !fsutil.InScope(rel, files) {
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
	return solidity.ScanFiles(sols)
}
