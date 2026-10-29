// Package bundle writes one Markdown bundle per hunting agent: the agent's
// source shard (paths and line counts, never inlined source), the binding
// table, the inventory items for those files, and the reference files the
// agent must read (operating procedure, lens, vector slice, shared rules).
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Agent is one hunting agent; the definitions live in profiles.json.
type Agent = profile.Lens

// Shard is a named set of repo-relative files.
type Shard struct {
	Name  string
	Kind  string
	Files []string
}

// Result describes one written bundle.
type Result struct {
	Agent  string `json:"agent"`
	Shard  string `json:"shard"`
	Path   string `json:"path"`
	Lines  int    `json:"lines"`
	Files  int    `json:"source_files"`
	Status string `json:"status"` // written, skipped
	Reason string `json:"reason,omitempty"`
}

// Options for Build.
type Options struct {
	Out     string // audit output directory holding inventory.json
	Skill   string // skill directory (holds references/)
	Profile string
}

// Build writes the bundles and returns one Result per agent.
func Build(opt Options) ([]Result, error) {
	b, err := os.ReadFile(filepath.Join(opt.Out, "inventory.json"))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w (run `inventory` first)", err)
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("bundle: inventory.json: %w", err)
	}
	binding, _ := os.ReadFile(filepath.Join(opt.Out, "binding-table.md"))
	periph := peripheral(opt.Out)
	refs := filepath.Join(opt.Skill, "references")
	read := func(rel string) (string, error) {
		x, err := os.ReadFile(filepath.Join(refs, rel))
		if err != nil {
			return "", fmt.Errorf("bundle: %w", err)
		}
		return string(x), nil
	}
	sop, err := read("senior-auditor-sop.md")
	if err != nil {
		return nil, err
	}
	rules, err := read("shared-rules.md")
	if err != nil {
		return nil, err
	}
	shards, err := Shards(&inv)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(opt.Out, "bundles")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var out []Result
	if _, ok := profile.Load().Profile(opt.Profile); !ok {
		return nil, fmt.Errorf("bundle: unknown profile %q (want one of %s)", opt.Profile, strings.Join(profile.Load().ProfileIDs(), ", "))
	}
	for _, a := range profile.Load().Lenses {
		if !a.In(opt.Profile) {
			out = append(out, Result{Agent: a.ID, Shard: a.Shard, Status: "skipped", Reason: "not in profile " + opt.Profile})
			continue
		}
		targets := shardsOf(shards, a.Shard)
		if len(targets) == 0 {
			out = append(out, Result{Agent: a.ID, Shard: a.Shard, Status: "skipped", Reason: "empty " + a.Shard + " shard"})
			continue
		}
		lens, err := read(a.File)
		if err != nil {
			return nil, err
		}
		slice := ""
		if a.Slice != "" {
			if slice, err = read(a.Slice); err != nil {
				return nil, err
			}
		}
		for _, sh := range targets {
			id := a.ID
			if sh.Name != sh.Kind {
				id = a.ID + "@" + sh.Name
			}
			md := render(&inv, a, id, sh, string(binding), periph, sop, lens, slice, rules, opt.Profile)
			p := filepath.Join(dir, safeName(id)+".md")
			if err := os.WriteFile(p, []byte(md), 0o644); err != nil {
				return nil, err
			}
			out = append(out, Result{Agent: id, Shard: sh.Name, Path: p, Lines: strings.Count(md, "\n"), Files: len(sh.Files), Status: "written"})
		}
	}
	return out, nil
}

func safeName(s string) string {
	r := strings.NewReplacer("/", "_", "@", "__", " ", "_")
	return r.Replace(s)
}

func shardsOf(all []Shard, kind string) []Shard {
	var out []Shard
	for _, s := range all {
		if s.Kind == kind && len(s.Files) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// Shards derives the circuit, integration, prover and all shards from an
// inventory. More than two circuit packages give one circuit shard each.
func Shards(inv *inventory.Inventory) ([]Shard, error) {
	root := inv.Repo
	circuitDirs := map[string]bool{}
	for _, c := range inv.Circuits {
		if !c.InTest {
			circuitDirs[path.Dir(c.Define.File)] = true
		}
	}
	goFiles, err := fsutil.Walk(root, fsutil.HasExt(".go"))
	if err != nil {
		return nil, err
	}
	perDir := map[string][]string{}
	var prover []string
	for _, f := range goFiles {
		if strings.HasSuffix(f.Rel, "_test.go") || !fsutil.InScope(f.Rel, inv.Scope) {
			continue
		}
		d := path.Dir(f.Rel)
		if circuitDirs[d] {
			perDir[d] = append(perDir[d], f.Rel)
			continue
		}
		if importsBackend(f.Abs) {
			prover = append(prover, f.Rel)
		}
	}
	// files outside circuit packages that hold hint sites or footguns used by
	// circuits belong to the circuit shard
	extra := map[string]bool{}
	for _, h := range inv.Hints {
		if !h.InTest && !circuitDirs[path.Dir(h.Pos.File)] {
			extra[h.Pos.File] = true
		}
	}
	for _, fg := range inv.Footguns {
		if !fg.InTest && fg.Circuit != "" && !circuitDirs[path.Dir(fg.Pos.File)] && strings.HasSuffix(fg.Pos.File, ".go") {
			extra[fg.Pos.File] = true
		}
	}
	var dirs []string
	for d := range perDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var shards []Shard
	var allCircuit []string
	for _, d := range dirs {
		allCircuit = append(allCircuit, perDir[d]...)
	}
	for f := range extra {
		allCircuit = appendUniq(allCircuit, f)
	}
	sort.Strings(allCircuit)
	if len(dirs) > 2 {
		for _, d := range dirs {
			files := append([]string{}, perDir[d]...)
			for f := range extra {
				files = appendUniq(files, f)
			}
			sort.Strings(files)
			shards = append(shards, Shard{Name: d, Kind: "circuit", Files: files})
		}
	} else {
		shards = append(shards, Shard{Name: "circuit", Kind: "circuit", Files: allCircuit})
	}
	var integ []string
	if inv.Contracts != nil {
		integ = append(integ, inv.Contracts.Files...)
	}
	if len(integ) > 0 {
		for _, c := range inv.Circuits {
			if !c.InTest {
				integ = appendUniq(integ, c.Decl.File)
			}
		}
	}
	sort.Strings(integ)
	shards = append(shards, Shard{Name: "integration", Kind: "integration", Files: integ})
	sort.Strings(prover)
	shards = append(shards, Shard{Name: "prover", Kind: "prover", Files: prover})
	var union []string
	for _, xs := range [][]string{allCircuit, integ, prover} {
		for _, f := range xs {
			union = appendUniq(union, f)
		}
	}
	sort.Strings(union)
	shards = append(shards, Shard{Name: "all", Kind: "all", Files: union})
	return shards, nil
}

func appendUniq(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func importsBackend(abs string) bool {
	af, err := parser.ParseFile(token.NewFileSet(), abs, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}
	for _, imp := range af.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/consensys/gnark/backend") || strings.HasPrefix(p, "github.com/consensys/gnark/test/unsafekzg") ||
			p == "github.com/consensys/gnark/frontend/cs/r1cs" || p == "github.com/consensys/gnark/frontend/cs/scs" {
			return true
		}
	}
	return false
}

func lineCount(abs string) int {
	b, err := os.ReadFile(abs)
	if err != nil {
		return -1
	}
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

func render(inv *inventory.Inventory, a Agent, id string, sh Shard, binding, periph, sop, lens, slice, rules, profile string) string {
	var b strings.Builder
	w := func(format string, x ...any) { fmt.Fprintf(&b, format, x...) }
	w("# Bundle %s\n\n", id)
	w("Agent id: `%s` · lens: `%s` · shard: `%s` · profile: `%s` · repository: `%s`\n\n", id, a.File, sh.Name, profile, inv.Repo)
	w("The repository is read-only for you (shared rules §1).\n\n")
	w("## 1. Source shard\n\nRead every file below in full before writing anything. Paths are relative to the repository root.\n\n| File | Lines |\n|---|---|\n")
	total := 0
	for _, f := range sh.Files {
		n := lineCount(filepath.Join(inv.Repo, filepath.FromSlash(f)))
		total += n
		w("| `%s` | %d |\n", f, n)
	}
	w("| **total** | %d |\n\n", total)
	w("%s\n\n", periph)
	if strings.TrimSpace(binding) != "" && sh.Kind != "prover" {
		w("## 2. Binding table\n\n%s\n\n", demote(binding))
	}
	w("## 3. Inventory items in this shard\n\n")
	in := map[string]bool{}
	for _, f := range sh.Files {
		in[f] = true
	}
	n := 0
	for _, h := range inv.Hints {
		if in[h.Pos.File] && !h.InTest {
			var bad []string
			for _, o := range h.Outputs {
				if o.Status != "reached" {
					bad = append(bad, "["+o.Index+"] "+o.Status)
				}
			}
			w("- hint %s at `%s:%d` (`%s`, outputs %s): **%s** %s\n", h.ID, h.Pos.File, h.Pos.Line, h.HintFunc, h.NbOutputs, h.Status, strings.Join(bad, ", "))
			n++
		}
	}
	for _, f := range inv.Footguns {
		if in[f.Pos.File] && !f.InTest {
			w("- %s %s at `%s:%d`: `%s`\n", f.Key, f.ID, f.Pos.File, f.Pos.Line, f.Snippet)
			n++
		}
	}
	if n == 0 {
		w("_none_\n")
	}
	w("\n")
	w("## 4. Operating procedure\n\n%s\n\n", demote(sop))
	w("## 5. Lens\n\n%s\n\n", demote(lens))
	if slice != "" {
		w("## 6. Vector slice\n\n%s\n\n", demote(slice))
	}
	w("## 7. Shared rules\n\n%s\n", demote(rules))
	return b.String()
}

// demote shifts Markdown headings down two levels so inlined files nest
// under the bundle's sections.
func demote(md string) string {
	lines := strings.Split(md, "\n")
	inFence := false
	for i, l := range lines {
		if strings.HasPrefix(l, "```") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(l, "#") {
			lines[i] = "##" + l
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// peripheral describes where agents find peripheral code. Hunters have no
// shell, so the gnark std directory is resolved here, from stack.json and the
// module cache, and stated as an absolute path or as unavailable.
func peripheral(out string) string {
	var b strings.Builder
	b.WriteString("Peripheral code (read on demand, never edit): vendored libraries under `vendor/` or Foundry `lib/`")
	var st detect.Stack
	raw, err := os.ReadFile(filepath.Join(out, "stack.json"))
	if err != nil || json.Unmarshal(raw, &st) != nil || len(st.Gnark.Versions) == 0 {
		b.WriteString("; gnark std at the version pinned in `go.mod` (no stack.json: version unknown).")
		return b.String()
	}
	cache := moduleCache()
	for _, v := range st.Gnark.Versions {
		if !strings.HasPrefix(v, "v") {
			fmt.Fprintf(&b, "; gnark %s: std source location unknown", v)
			continue
		}
		dir := filepath.Join(cache, "github.com", "consensys", "gnark@"+v, "std")
		if st, err := os.Stat(dir); cache != "" && err == nil && st.IsDir() {
			fmt.Fprintf(&b, "; gnark std at the pinned %s: `%s`", v, dir)
		} else {
			fmt.Fprintf(&b, "; gnark std at the pinned %s is **not available** (not in the module cache): do not reason about std internals from memory, write a LEAD whose `unverified:` names the std function", v)
		}
	}
	b.WriteString(".")
	return b.String()
}

// moduleCache returns GOMODCACHE: the environment, else `go env`, else
// GOPATH/pkg/mod.
func moduleCache() string {
	if c := os.Getenv("GOMODCACHE"); c != "" {
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o, err := exec.CommandContext(ctx, "go", "env", "GOMODCACHE").Output(); err == nil {
		if c := strings.TrimSpace(string(o)); c != "" {
			return c
		}
	}
	gp := os.Getenv("GOPATH")
	if gp == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gp = filepath.Join(h, "go")
	}
	return filepath.Join(strings.Split(gp, string(os.PathListSeparator))[0], "pkg", "mod")
}
