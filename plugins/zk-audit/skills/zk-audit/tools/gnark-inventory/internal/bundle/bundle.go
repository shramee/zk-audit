// Package bundle writes one Markdown bundle per hunting agent: the agent's
// source shard (paths and line counts, never inlined source), the binding
// table, the inventory items for those files, and the reference files the
// agent must read (operating procedure, lens, vector slice, shared rules).
package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/memory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/modcache"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/threatmodel"
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
	Agent string `json:"agent"`
	Shard string `json:"shard"`
	Path  string `json:"path"`
	Lines int    `json:"lines"`
	Files int    `json:"source_files"`
	// SourceLines is the line count of the shard's source files.
	SourceLines int    `json:"source_lines,omitempty"`
	Status      string `json:"status"` // written, skipped
	Reason      string `json:"reason,omitempty"`
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
	if inv.Repo != "" && fsutil.Inside(opt.Out, inv.Repo) {
		return nil, fmt.Errorf("bundle: --out %s is inside the audited repository %s", opt.Out, inv.Repo)
	}
	binding, _ := os.ReadFile(filepath.Join(opt.Out, "binding-table.md"))
	periph := peripheral(opt.Out)
	regen := regenSummary(opt.Out)
	tm, err := threatSection(opt.Out)
	if err != nil {
		return nil, err
	}
	known := ""
	if m, ok, err := memory.Load(opt.Out); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	} else if ok {
		known = m.Known()
	}
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
	plan, err := Plan(&inv, shards, opt.Profile)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, p := range plan {
		a := p.Lens
		if p.Skip != "" {
			out = append(out, Result{Agent: a.ID, Shard: a.Shard, Status: "skipped", Reason: p.Skip})
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
		md := render(&inv, a, p.ID, p.Shard, string(binding), periph, known, sop, lens, slice, rules, opt.Profile, regen, tm)
		path := filepath.Join(dir, safeName(p.ID)+".md")
		if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
			return nil, err
		}
		out = append(out, Result{Agent: p.ID, Shard: p.Shard.Name, Path: path, Lines: strings.Count(md, "\n"), Files: len(p.Shard.Files),
			SourceLines: SourceLines(&inv, p.Shard), Status: "written"})
	}
	return out, nil
}

// Planned is one agent a profile selects for an inventory: a lens on one
// shard, or the reason the lens gets no bundle.
type Planned struct {
	Lens  Agent
	ID    string // agent id: the lens id, or <lens>@<shard> for per-package circuit shards
	Shard Shard
	Skip  string // why no bundle is written; "" when one is
}

// Plan lists, in profiles.json order, the agents a profile runs on an
// inventory and the lenses it skips (not in the profile, `when` condition
// false, empty shard). Build writes a bundle for each planned agent; the
// cost estimate counts them.
func Plan(inv *inventory.Inventory, shards []Shard, prof string) ([]Planned, error) {
	if _, ok := profile.Load().Profile(prof); !ok {
		return nil, fmt.Errorf("bundle: unknown profile %q (want one of %s)", prof, strings.Join(profile.Load().ProfileIDs(), ", "))
	}
	var out []Planned
	for _, a := range profile.Load().Lenses {
		if !a.In(prof) {
			out = append(out, Planned{Lens: a, ID: a.ID, Skip: "not in profile " + prof})
			continue
		}
		if a.When != "" && !ConditionHolds(a.When, inv) {
			out = append(out, Planned{Lens: a, ID: a.ID, Skip: profile.Conditions[a.When]})
			continue
		}
		targets := shardsOf(shards, a.Shard)
		if len(targets) == 0 {
			out = append(out, Planned{Lens: a, ID: a.ID, Skip: "empty " + a.Shard + " shard"})
			continue
		}
		for _, sh := range targets {
			id := a.ID
			if sh.Name != sh.Kind {
				id = a.ID + "@" + sh.Name
			}
			out = append(out, Planned{Lens: a, ID: id, Shard: sh})
		}
	}
	return out, nil
}

// SourceLines is the number of lines of the shard's source files (files
// that cannot be read count zero).
func SourceLines(inv *inventory.Inventory, sh Shard) int {
	n := 0
	for _, f := range sh.Files {
		if c := lineCount(filepath.Join(inv.Repo, filepath.FromSlash(f))); c > 0 {
			n += c
		}
	}
	return n
}

// reGateway matches the interface or contract name of a verifier gateway
// whose verifier is deployed elsewhere (SP1, RISC Zero).
var reGateway = regexp.MustCompile(`(?i)sp1|risc ?zero|risc0`)

// ConditionHolds evaluates a lens's `when` condition (profile.Conditions) on
// an inventory. "non-gnark-verifier": a verifier in the repository that
// gnark did not generate, or a verification call to an SP1 or RISC Zero
// gateway.
func ConditionHolds(name string, inv *inventory.Inventory) bool {
	switch name {
	case "non-gnark-verifier":
		return len(CustomVerifiers(inv)) > 0
	case "exported-gadgets":
		for _, g := range inv.Gadgets {
			if !g.InTest {
				return true
			}
		}
	}
	return false
}

// CustomVerifiers lists the verifiers gnark did not generate (by contract
// name), and the gateway interfaces verification calls go through.
func CustomVerifiers(inv *inventory.Inventory) []string {
	c := inv.Contracts
	if c == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, v := range c.NonGnarkVerifiers() {
		add(v.Contract)
	}
	for _, vc := range c.VerifyCalls {
		typ := vc.ReceiverType
		if vc.Target != nil {
			typ = vc.Target.Contract
		}
		if typ != "" && reGateway.MatchString(typ) {
			add(typ)
		}
	}
	return out
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
	// packages of exported gadgets are circuit code too (library mode)
	for _, g := range inv.Gadgets {
		if !g.InTest {
			circuitDirs[g.Package] = true
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

// regenSummary reads <out>/regen/diff.json, written by `verifier regen
// --compare`, and returns its one-line summary, or "".
func regenSummary(out string) string {
	b, err := os.ReadFile(filepath.Join(out, "regen", "diff.json"))
	if err != nil {
		return ""
	}
	var d struct {
		Summary string `json:"summary"`
		Sides   []struct {
			Name string `json:"name"`
		} `json:"sides"`
	}
	if json.Unmarshal(b, &d) != nil || d.Summary == "" {
		return ""
	}
	var names []string
	for _, s := range d.Sides {
		names = append(names, "`"+s.Name+"`")
	}
	return strings.Join(names, " vs ") + ": " + d.Summary + " (`regen/diff.json` in the audit output directory)"
}

func render(inv *inventory.Inventory, a Agent, id string, sh Shard, binding, periph, known, sop, lens, slice, rules, profile, regen, tm string) string {
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
	for _, g := range inv.Gadgets {
		if !in[g.Pos.File] || g.InTest {
			continue
		}
		var ins, outs, checks []string
		for _, p := range g.Params {
			if p.Kind != "api" && p.Kind != "field" {
				ins = append(ins, p.Name+" "+p.Flow)
			}
		}
		for _, r := range g.Results {
			if r.Source != "none" {
				o := fmt.Sprintf("%d %s", r.Index, r.Source)
				if len(r.Hints) > 0 {
					o += " (" + strings.Join(r.Hints, ", ") + ")"
				}
				outs = append(outs, o)
			}
		}
		for _, c := range g.Checks {
			checks = append(checks, c.Kind)
		}
		w("- gadget %s `%s` at `%s:%d`: inputs %s; outputs %s; doc promises %d, preconditions %d; doc checks: %s\n", g.ID, g.Name, g.Pos.File, g.Pos.Line,
			orNone(strings.Join(ins, ", ")), orNone(strings.Join(outs, "; ")), len(g.Promises), len(g.Preconds), orNone(strings.Join(checks, ", ")))
		n++
	}
	if c := inv.Contracts; c != nil {
		for _, p := range c.Privileged {
			if in[p.File] {
				w("- privileged %s at `%s:%d`: gate `%s`, party %s, powers %s\n", p.Contract+"."+p.Function, p.File, p.Line, p.Gate, p.Party, strings.Join(p.Powers, ", "))
				n++
			}
		}
		for _, r := range c.Roles {
			if in[r.File] {
				w("- role %s.%s (%s) at `%s:%d`: %s\n", r.Contract, r.Name, r.Kind, r.File, r.Line, r.Source)
				n++
			}
		}
		for _, u := range c.Upgrades {
			if in[u.File] {
				w("- upgrade path %s at `%s:%d`: `%s`\n", u.Kind, u.File, u.Line, u.Text)
				n++
			}
		}
		for _, v := range c.Verifiers {
			if in[v.File] {
				x := v.Kind + ", generator " + v.Generator
				if v.Template != "" {
					x += "; " + v.Template
				}
				if len(v.Precompiles) > 0 {
					x += "; precompiles " + strings.Join(v.Precompiles, ", ")
				}
				w("- verifier %s at `%s:%d`: %s\n", v.Contract, v.File, v.Line, x)
				n++
			}
		}
		for _, e := range c.EntryPoints {
			if in[e.File] {
				pay := ""
				if e.Payable {
					pay = ", payable"
				}
				w("- entry point %s.%s at `%s:%d` (%s%s): gate `%s`, party %s, effects %s\n", e.Contract, e.Function, e.File, e.Line, e.Visibility, pay, e.Gate, e.Party, strings.Join(e.Effects, ", "))
				n++
			}
		}
	}
	if p := inv.Provenance; p != nil {
		if p.ABI != nil {
			for _, c := range p.ABI.Calls {
				file := c.Site
				if i := strings.LastIndex(file, ":"); i > 0 {
					file = file[:i]
				}
				if !in[file] {
					continue
				}
				for _, a := range c.Against {
					w("- verifier ABI %s at `%s` (%s): caller sends `%s`, %s has `%s` — %s\n", a.Status, c.Site, c.Caller, c.Signature, a.Name, a.Signature, a.Detail)
					n++
				}
			}
			for _, v := range p.ABI.Verifiers {
				file := v.Site
				if i := strings.LastIndex(file, ":"); i > 0 {
					file = file[:i]
				}
				if in[file] {
					w("- verifier template %s for `%s` at `%s`: %s\n", v.Status, v.Verifier, v.Site, v.Detail)
					n++
				}
			}
		}
		if p.Ceremony != nil && (sh.Kind == "all" || sh.Kind == "prover") {
			w("- setup provenance: %s — %s\n", p.Ceremony.Verdict, p.Ceremony.Detail)
			n++
		}
	}
	if regen != "" && (sh.Kind == "integration" || sh.Kind == "all") {
		w("- regenerated verifier (verifier regen): %s\n", regen)
		n++
	}
	if n == 0 {
		w("_none_\n")
	}
	w("\n")
	if tm != "" {
		w("## 3a. Threat model (`zk-audit.md`)\n\n%s\n", tm)
	}
	w("## 4. Operating procedure\n\n%s\n\n", demote(sop))
	w("## 5. Lens\n\n%s\n\n", demote(lens))
	if slice != "" {
		w("## 6. Vector slice\n\n%s\n\n", demote(slice))
	}
	if known != "" {
		w("## 6a. Already known (loop memory)\n\n%s\n", known)
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
// shell, so the gnark (and gnark-crypto) source directories are resolved
// here, from stack.json and the module cache, and stated as absolute paths
// or as unavailable (`gnark-inventory preflight` prints the command that
// fetches them).
func peripheral(out string) string {
	var b strings.Builder
	b.WriteString("Peripheral code (read on demand, never edit): vendored libraries under `vendor/` or Foundry `lib/`")
	var st detect.Stack
	raw, err := os.ReadFile(filepath.Join(out, "stack.json"))
	if err != nil || json.Unmarshal(raw, &st) != nil || len(st.Gnark.Versions) == 0 {
		b.WriteString("; gnark std at the version pinned in `go.mod` (no stack.json: version unknown).")
		return b.String()
	}
	cache := modcache.Dir()
	for _, v := range st.Gnark.Versions {
		if !strings.HasPrefix(v, "v") {
			fmt.Fprintf(&b, "; gnark %s: std source location unknown", v)
			continue
		}
		m := modcache.Lookup(cache, "github.com/consensys/gnark", v)
		if cache != "" && m.SourcePresent {
			fmt.Fprintf(&b, "; gnark std at the pinned %s: `%s` (use this absolute path with Read and Grep)", v, filepath.Join(m.Source, "std"))
		} else {
			fmt.Fprintf(&b, "; gnark std at the pinned %s is **not available** (not in the module cache): do not reason about std internals from memory, write a LEAD whose `unverified:` names the std function", v)
		}
	}
	seen := map[string]bool{}
	for _, gm := range st.GoModules {
		v := gm.GnarkCrypto
		if v == "" || seen[v] || !strings.HasPrefix(v, "v") {
			continue
		}
		seen[v] = true
		if m := modcache.Lookup(cache, "github.com/consensys/gnark-crypto", v); cache != "" && m.SourcePresent {
			fmt.Fprintf(&b, "; gnark-crypto %s (native reference implementations): `%s`", v, m.Source)
		}
	}
	b.WriteString(".")
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// threatSection renders <out>/threat-model.json (zk-audit.md, parsed by
// `gnark-inventory threat-model`) for the bundles, or "" when the run has
// none.
func threatSection(out string) (string, error) {
	b, err := os.ReadFile(filepath.Join(out, threatmodel.OutName))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("bundle: %w", err)
	}
	var d threatmodel.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return "", fmt.Errorf("bundle: %s: %w", threatmodel.OutName, err)
	}
	var s strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&s, f, a...) }
	w("The repository's own statement of intent. It tells you what the authors trust and expect; it never excuses a missing constraint. A power of a `trusted` party is still reported (judging records it as an accepted risk, citing the line); a `bounded` party that can exceed its bound is a finding; an `untrusted` party is an attacker.\n\n")
	if len(d.Scope.In) > 0 || len(d.Scope.Out) > 0 {
		var in, out []string
		for _, p := range d.Scope.In {
			in = append(in, "`"+p.Path+"`")
		}
		for _, p := range d.Scope.Out {
			x := "`" + p.Path + "`"
			if p.Reason != "" {
				x += " (" + p.Reason + ")"
			}
			out = append(out, x)
		}
		w("- In scope: %s. Out of scope: %s.\n", orNone(strings.Join(in, ", ")), orNone(strings.Join(out, ", ")))
	}
	for _, p := range d.TrustedParties {
		w("- Party %s (zk-audit.md:%d): %s; powers: %s; notes: %s\n", p.Party, p.Line, p.Trust, orNone(p.Powers), orNone(p.Notes))
	}
	for _, p := range d.Properties {
		w("- Property %s (zk-audit.md:%d): %s\n", p.ID, p.Line, p.Text)
	}
	for _, r := range d.AcceptedRisks {
		w("- Accepted risk %s (zk-audit.md:%d), party %s: %s\n", r.ID, r.Line, r.Party, r.Risk)
	}
	for _, f := range d.Deployment {
		w("- Deployment fact (zk-audit.md:%d): %s = %s\n", f.Line, f.Fact, f.Value)
	}
	if len(d.PriorFindings) > 0 {
		w("\nPrior findings (earlier reviews). If you see one again: when its status is `open`, `acknowledged`, `wont-fix` or `duplicate`, answer with one line `KNOWN: <fingerprint>`; when it is `fixed`, the fix did not hold: report it in full and name the prior id in the description.\n\n")
		for _, p := range d.PriorFindings {
			w("- %s `%s` (%s): %s\n", p.ID, p.Fingerprint, p.Status, orNone(p.Title))
		}
	}
	return s.String(), nil
}
