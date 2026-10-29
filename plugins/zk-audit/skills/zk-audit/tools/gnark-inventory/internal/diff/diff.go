// Package diff compares two revisions of a target repository and flags the
// high-risk triggers of diff mode deterministically: removed or newly
// conditional constraint calls, removed range checks, changed public inputs,
// new hints, gnark version changes, changed verifier contracts, verifying
// keys and verifier call sites. It reads git objects only (git cat-file), so
// it never touches the working tree, the index or hooks.
package diff

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	goprinter "go/printer"
	"go/token"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/gomod"
)

// Trigger kinds.
const (
	ConstraintRemoved     = "constraint-removed"
	ConstraintConditional = "constraint-now-conditional"
	RangeCheckRemoved     = "range-check-removed"
	PublicInputChanged    = "public-input-changed"
	HintAdded             = "hint-added"
	GnarkVersion          = "gnark-version-changed"
	VerifierChanged       = "verifier-contract-changed"
	VKChanged             = "verifying-key-changed"
	VerifyCallChanged     = "verify-call-changed"
)

// Kinds lists every trigger kind with the agent pass it calls for.
var Kinds = map[string]string{
	ConstraintRemoved:     "an Assert*/constraint call removed from a function",
	ConstraintConditional: "a constraint call moved under a Go if (compile-time branch)",
	RangeCheckRemoved:     "a range check or bit decomposition removed",
	PublicInputChanged:    "a public input added, removed, re-ordered or re-tagged",
	HintAdded:             "a new hint call or hint registration",
	GnarkVersion:          "a gnark or gnark-crypto version change in go.mod",
	VerifierChanged:       "a verifier contract regenerated or edited",
	VKChanged:             "a verifying-key file changed",
	VerifyCallChanged:     "a verifier call site, verifier address/setter or public-input array changed",
}

// File is one changed path.
type File struct {
	Status  string `json:"status"` // A, M, D, R
	Path    string `json:"path"`
	OldPath string `json:"old_path,omitempty"`
}

// Trigger is one high-risk change.
type Trigger struct {
	Kind   string `json:"kind"`
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"` // line in the head revision (0: removed file or file-level)
	Scope  string `json:"scope,omitempty"`
	Detail string `json:"detail"`
}

// Result is the whole comparison.
type Result struct {
	Repo      string         `json:"repo"`
	Base      string         `json:"base"`
	Head      string         `json:"head"`
	BaseSHA   string         `json:"base_sha"`
	HeadSHA   string         `json:"head_sha"`
	MergeBase string         `json:"merge_base"`
	Files     []File         `json:"files"`
	Triggers  []Trigger      `json:"triggers"`
	Counts    map[string]int `json:"counts"`
}

// Git runs git read-only on repo: no pager, no external diff or textconv
// drivers, no fsmonitor or hooks from the repository's config.
func Git(repo string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	full := append([]string{"-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=",
		"--no-pager", "-C", repo}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EXTERNAL_DIFF=", "GIT_OPTIONAL_LOCKS=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func rev(repo, r string) (string, error) {
	if strings.HasPrefix(r, "-") {
		return "", fmt.Errorf("%q is not a revision", r)
	}
	out, err := Git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", r+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("unknown revision %q", r)
	}
	return strings.TrimSpace(string(out)), nil
}

// show returns a file at a revision, or nil when it does not exist there.
func show(repo, sha, p string) []byte {
	out, err := Git(repo, "cat-file", "blob", sha+":"+p)
	if err != nil {
		return nil
	}
	return out
}

// Compare lists the changes between the merge base of base and head, and
// head, and the triggers among them.
func Compare(repo, base, head string) (*Result, error) {
	if head == "" {
		head = "HEAD"
	}
	b, err := rev(repo, base)
	if err != nil {
		return nil, err
	}
	h, err := rev(repo, head)
	if err != nil {
		return nil, err
	}
	mbOut, err := Git(repo, "merge-base", b, h)
	if err != nil {
		return nil, err
	}
	mb := strings.TrimSpace(string(mbOut))
	res := &Result{Repo: repo, Base: base, Head: head, BaseSHA: b, HeadSHA: h, MergeBase: mb, Files: []File{}, Triggers: []Trigger{}, Counts: map[string]int{}}
	ns, err := Git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-status", "-z", mb, h)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimRight(string(ns), "\x00"), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		res.Files = append(res.Files, File{Status: parts[i][:1], Path: parts[i+1]})
	}
	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	for _, f := range res.Files {
		var old, cur []byte
		if f.Status != "A" {
			old = show(repo, mb, f.Path)
		}
		if f.Status != "D" {
			cur = show(repo, h, f.Path)
		}
		res.Triggers = append(res.Triggers, fileTriggers(f.Path, old, cur)...)
	}
	sort.SliceStable(res.Triggers, func(i, j int) bool {
		a, c := res.Triggers[i], res.Triggers[j]
		if a.File != c.File {
			return a.File < c.File
		}
		if a.Line != c.Line {
			return a.Line < c.Line
		}
		if a.Kind != c.Kind {
			return a.Kind < c.Kind
		}
		return a.Detail < c.Detail
	})
	for _, t := range res.Triggers {
		res.Counts[t.Kind]++
	}
	return res, nil
}

func fileTriggers(p string, old, cur []byte) []Trigger {
	base := path.Base(p)
	var out []Trigger
	switch {
	case base == "go.mod":
		out = append(out, goModTriggers(p, old, cur)...)
	case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
		out = append(out, goTriggers(p, old, cur)...)
	case strings.HasSuffix(p, ".sol"):
		out = append(out, solTriggers(p, old, cur)...)
	}
	if reVK.MatchString(base) {
		out = append(out, Trigger{Kind: VKChanged, File: p, Detail: "verifying-key file " + changeWord(old, cur)})
	}
	return out
}

func changeWord(old, cur []byte) string {
	switch {
	case old == nil:
		return "added"
	case cur == nil:
		return "removed"
	}
	return "changed"
}

var reVK = regexp.MustCompile(`(?i)(^|[._-])(vk|vkey|verifying[_-]?key|verification[_-]?key)([._-]|$)|\.vk$`)

// --- go.mod

var gnarkModules = []string{"github.com/consensys/gnark", "github.com/consensys/gnark-crypto"}

func goModTriggers(p string, old, cur []byte) []Trigger {
	parse := func(b []byte) *gomod.File {
		if b == nil {
			return &gomod.File{}
		}
		f, err := gomod.Parse(bytes.NewReader(b))
		if err != nil {
			return &gomod.File{}
		}
		return f
	}
	o, c := parse(old), parse(cur)
	var out []Trigger
	for _, m := range gnarkModules {
		ov, orep, _ := o.Version(m)
		cv, crep, _ := c.Version(m)
		if ov != cv || orep != crep {
			d := fmt.Sprintf("%s %s → %s", m, verStr(ov, orep), verStr(cv, crep))
			out = append(out, Trigger{Kind: GnarkVersion, File: p, Line: lineOf(cur, m), Detail: d})
		}
	}
	return out
}

func verStr(v, rep string) string {
	switch {
	case v == "" && rep == "":
		return "(none)"
	case rep != "":
		return strings.TrimSpace(v + " (replaced by " + rep + ")")
	}
	return v
}

func lineOf(b []byte, needle string) int {
	for i, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 0
}

// --- Go

// constraintNames are calls that emit constraints (the inventory's sinks).
var constraintNames = map[string]bool{
	"AssertIsEqual": true, "AssertIsDifferent": true, "AssertIsBoolean": true, "AssertIsCrumb": true,
	"AssertIsLessOrEqual": true, "AssertIsInRange": true, "ToBinary": true, "ToBase": true,
	"FromBinary": true, "FromBase": true, "Check": true, "ModAssertIsEqual": true,
	"AssertEvalIsZero": true, "MustBeLessOrEqCst": true, "AssertIsOnCurve": true, "AssertProof": true,
	"AssertIsLess": true, "AssertIsLessEq": true, "AssertIsOnG1": true, "AssertIsOnG2": true,
	"AssertIsOnTwist": true, "AssertIsZero": true, "AssertIsEqualMod": true,
	"AssertIsOnCurveG1": true, "AssertFinalExponentiationIsOne": true, "PairingCheck": true,
}

// rangeNames are the range checks and decompositions among them.
var rangeNames = map[string]bool{
	"ToBinary": true, "ToBase": true, "Check": true, "AssertIsLessOrEqual": true, "AssertIsInRange": true,
	"MustBeLessOrEqCst": true, "AssertIsLess": true, "AssertIsLessEq": true, "AssertIsBoolean": true, "AssertIsCrumb": true,
}

var hintNames = map[string]bool{
	"NewHint": true, "NewHintWithNativeInput": true, "NewHintWithNativeOutput": true, "NewHintGeneric": true, "RegisterHint": true,
}

type callStat struct {
	total, underIf int
	lines          []int // head lines of the calls
}

// goFacts are the per-function call counts and the public-input layout of
// one version of a file.
type goFacts struct {
	calls  map[string]map[string]*callStat // func -> call name -> stat
	public map[string][]string             // struct -> ordered "name type tag" of gnark-tagged fields
	pubPos map[string]int
}

func parseGo(p string, src []byte) *goFacts {
	g := &goFacts{calls: map[string]map[string]*callStat{}, public: map[string][]string{}, pubPos: map[string]int{}}
	if src == nil {
		return g
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
	if f == nil || err != nil && f.Decls == nil {
		return g
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				name = recvName(d.Recv.List[0].Type) + "." + name
			}
			m := map[string]*callStat{}
			walkCalls(fset, d.Body, 0, m)
			g.calls[name] = m
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				var fields []string
				for _, fl := range st.Fields.List {
					tag := gnarkTag(fl.Tag)
					if tag == "" {
						continue
					}
					typ := exprString(fset, fl.Type)
					names := []string{"(embedded)"}
					if len(fl.Names) > 0 {
						names = nil
						for _, n := range fl.Names {
							names = append(names, n.Name)
						}
					}
					for _, n := range names {
						fields = append(fields, n+" "+typ+" `gnark:\""+tag+"\"`")
					}
				}
				if len(fields) > 0 {
					g.public[ts.Name.Name] = fields
					g.pubPos[ts.Name.Name] = fset.Position(ts.Pos()).Line
				}
			}
		}
	}
	return g
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	}
	return "?"
}

func gnarkTag(t *ast.BasicLit) string {
	if t == nil {
		return ""
	}
	s := strings.Trim(t.Value, "`")
	i := strings.Index(s, `gnark:"`)
	if i < 0 {
		return ""
	}
	s = s[i+len(`gnark:"`):]
	if j := strings.IndexByte(s, '"'); j >= 0 {
		return s[:j]
	}
	return ""
}

func isPublic(field string) bool {
	i := strings.Index(field, "`gnark:\"")
	return i >= 0 && strings.Contains(field[i:], "public")
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	if err := goprinter.Fprint(&b, fset, e); err != nil {
		return "?"
	}
	return b.String()
}

func walkCalls(fset *token.FileSet, n ast.Node, depth int, m map[string]*callStat) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.IfStmt:
			if x.Init != nil {
				walkCalls(fset, x.Init, depth, m)
			}
			walkCalls(fset, x.Cond, depth, m)
			walkCalls(fset, x.Body, depth+1, m)
			if x.Else != nil {
				walkCalls(fset, x.Else, depth+1, m)
			}
			return false
		case *ast.CallExpr:
			name := ""
			switch fn := x.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if constraintNames[name] || hintNames[name] {
				s := m[name]
				if s == nil {
					s = &callStat{}
					m[name] = s
				}
				s.total++
				if depth > 0 {
					s.underIf++
				}
				s.lines = append(s.lines, fset.Position(x.Pos()).Line)
			}
		}
		return true
	})
}

func goTriggers(p string, old, cur []byte) []Trigger {
	o, c := parseGo(p, old), parseGo(p, cur)
	var out []Trigger
	funcs := map[string]bool{}
	for f := range o.calls {
		funcs[f] = true
	}
	for f := range c.calls {
		funcs[f] = true
	}
	for _, fn := range sortedKeys(funcs) {
		oc, cc := o.calls[fn], c.calls[fn]
		names := map[string]bool{}
		for n := range oc {
			names[n] = true
		}
		for n := range cc {
			names[n] = true
		}
		for _, n := range sortedKeys(names) {
			var os_, cs callStat
			if x := oc[n]; x != nil {
				os_ = *x
			}
			if x := cc[n]; x != nil {
				cs = *x
			}
			line := 0
			if len(cs.lines) > 0 {
				line = cs.lines[0]
			}
			switch {
			case hintNames[n] && cs.total > os_.total:
				out = append(out, Trigger{Kind: HintAdded, File: p, Line: lastLine(cs.lines), Scope: fn, Detail: fmt.Sprintf("%s calls %d → %d", n, os_.total, cs.total)})
			case hintNames[n]:
			case cs.total < os_.total:
				kind := ConstraintRemoved
				if rangeNames[n] {
					kind = RangeCheckRemoved
				}
				where := "function removed"
				if cc != nil {
					where = fmt.Sprintf("%d → %d calls", os_.total, cs.total)
				}
				out = append(out, Trigger{Kind: kind, File: p, Line: line, Scope: fn, Detail: n + ": " + where})
			case cs.underIf > os_.underIf:
				out = append(out, Trigger{Kind: ConstraintConditional, File: p, Line: line, Scope: fn,
					Detail: fmt.Sprintf("%s under a Go if: %d → %d of %d calls", n, os_.underIf, cs.underIf, cs.total)})
			}
		}
	}
	structs := map[string]bool{}
	for s := range o.public {
		structs[s] = true
	}
	for s := range c.public {
		structs[s] = true
	}
	for _, s := range sortedKeys(structs) {
		ow, cw := o.public[s], c.public[s]
		if strings.Join(ow, "\n") == strings.Join(cw, "\n") {
			continue
		}
		op, cp := filterPublic(ow), filterPublic(cw)
		if strings.Join(op, "\n") == strings.Join(cp, "\n") {
			continue // only secret fields changed
		}
		out = append(out, Trigger{Kind: PublicInputChanged, File: p, Line: c.pubPos[s], Scope: s, Detail: describePublic(op, cp)})
	}
	return out
}

func filterPublic(fields []string) []string {
	var out []string
	for _, f := range fields {
		if isPublic(f) {
			out = append(out, f)
		}
	}
	return out
}

func describePublic(o, c []string) string {
	name := func(f string) string { return strings.SplitN(f, " ", 2)[0] }
	on, cn := map[string]string{}, map[string]string{}
	var onames, cnames []string
	for _, f := range o {
		on[name(f)] = f
		onames = append(onames, name(f))
	}
	for _, f := range c {
		cn[name(f)] = f
		cnames = append(cnames, name(f))
	}
	var parts []string
	for _, n := range onames {
		if _, ok := cn[n]; !ok {
			parts = append(parts, "removed "+n)
		} else if cn[n] != on[n] {
			parts = append(parts, "changed "+n+" ("+on[n]+" → "+cn[n]+")")
		}
	}
	for _, n := range cnames {
		if _, ok := on[n]; !ok {
			parts = append(parts, "added "+n)
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "re-ordered")
	}
	return fmt.Sprintf("public inputs [%s] → [%s]: %s", strings.Join(onames, ", "), strings.Join(cnames, ", "), strings.Join(parts, "; "))
}

func lastLine(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	return xs[len(xs)-1]
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Solidity

var (
	reVerifierContract = regexp.MustCompile(`(?i)function\s+verify(Proof|CompressedProof)?\s*\(|\b(alpha1|ALPHA_X|BETA_NEG|DELTA_NEG|vk_gamma|VK_)|\bPairing\b|precompile|ecPairing`)
	reVerifyCallLine   = regexp.MustCompile(`(?i)\.verify(Proof|CompressedProof)?\s*\(|\bverifier\s*=|setVerifier|\bIVerifier\b|\bverifier\b.*\(|publicInputs?\s*\[|input\s*\[\s*\d+\s*\]\s*=|uint256\[\s*\d+\s*\]\s+memory`)
)

func solTriggers(p string, old, cur []byte) []Trigger {
	var out []Trigger
	isVerifier := func(b []byte) bool {
		return b != nil && len(reVerifierContract.FindAllIndex(b, 3)) >= 2
	}
	if isVerifier(old) || isVerifier(cur) {
		out = append(out, Trigger{Kind: VerifierChanged, File: p, Detail: "verifier contract " + changeWord(old, cur) + "; regenerate it from the circuit and the VK and compare"})
		return out
	}
	oldLines, curLines := lineSet(old), lineSet(cur)
	seen := map[string]bool{}
	for i, l := range strings.Split(string(cur), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || oldLines[t] || !reVerifyCallLine.MatchString(t) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, Trigger{Kind: VerifyCallChanged, File: p, Line: i + 1, Detail: "added or changed: " + clip(t)})
	}
	for _, l := range strings.Split(string(old), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || curLines[t] || !reVerifyCallLine.MatchString(t) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, Trigger{Kind: VerifyCallChanged, File: p, Detail: "removed: " + clip(t)})
	}
	return out
}

func lineSet(b []byte) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		m[strings.TrimSpace(l)] = true
	}
	return m
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

// Markdown renders the result for the orchestrator and the report.
func (r *Result) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Diff %s..%s\n\nmerge base `%s` · head `%s` · %d changed files · %d triggers\n\n", r.Base, r.Head, short(r.MergeBase), short(r.HeadSHA), len(r.Files), len(r.Triggers))
	b.WriteString("## High-risk triggers\n\n")
	if len(r.Triggers) == 0 {
		b.WriteString("None detected by the tool. The diff still gets the standard review of the changed files.\n\n")
	} else {
		b.WriteString("Each trigger gets a dedicated agent pass.\n\n| Kind | Location | Scope | Detail |\n|---|---|---|---|\n")
		for _, t := range r.Triggers {
			loc := "`" + t.File + "`"
			if t.Line > 0 {
				loc = fmt.Sprintf("`%s:%d`", t.File, t.Line)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", t.Kind, loc, cellText(t.Scope), cellText(t.Detail))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Changed files\n\n")
	for _, f := range r.Files {
		fmt.Fprintf(&b, "- %s `%s`\n", f.Status, f.Path)
	}
	return b.String()
}

func cellText(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
