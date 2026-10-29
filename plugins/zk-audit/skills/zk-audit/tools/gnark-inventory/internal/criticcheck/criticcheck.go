// Package criticcheck computes, without a model, what the coverage critic
// used to look for by reading: ledger units nobody started, covered units
// with no saved agent output, and inventory items (hint sites, public
// inputs, verifier calls, privileged functions, entry points, gadgets) that
// no saved agent output mentions. The model critic is then asked only for
// lens-level gaps, and every item listed here needs a recorded decision in
// the ledger (run in the targeted wave, deferred, or dismissed with a
// reason) before the report; Verify checks that.
package criticcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/agents"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/ledger"
)

// File is the check's output in the audit directory.
const File = "critic-check.json"

// Item is one missing unit, in the coverage critic's format plus where it
// came from.
type Item struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // unit-open, unit-no-output, hint, public-input, verify-call, privileged, entry-point, gadget
	Why    string `json:"why"`
	Lens   string `json:"lens"`
	Path   string `json:"path,omitempty"`
	Unit   string `json:"unit,omitempty"` // the ledger unit that covers the item, if any
	Add    string `json:"add,omitempty"`  // the ledger add command when no unit covers it
	Source string `json:"source"`         // always "tool"
}

// Result is critic-check.json.
type Result struct {
	SchemaVersion string         `json:"schema_version"`
	MissingUnits  []Item         `json:"missing_units"`
	Counts        map[string]int `json:"counts"`
	Outputs       int            `json:"agent_outputs_read"`
}

// corpus is the saved agent outputs, for mention checks.
type corpus struct {
	texts []string
	refs  map[string][]int // file (as written) -> cited lines
}

var reRef = regexp.MustCompile(`([A-Za-z0-9_./-]+\.(?:go|sol)):(\d+)`)

func loadOutputs(out string) (*corpus, *agents.Index, error) {
	idx, err := agents.Load(out)
	if err != nil {
		return nil, nil, err
	}
	c := &corpus{refs: map[string][]int{}}
	files, _ := filepath.Glob(filepath.Join(out, "agents", "*.md"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		t := string(b)
		c.texts = append(c.texts, t)
		for _, m := range reRef.FindAllStringSubmatch(t, -1) {
			n, _ := strconv.Atoi(m[2])
			c.refs[m[1]] = append(c.refs[m[1]], n)
		}
	}
	return c, idx, nil
}

// cites reports whether an output cites file within 3 lines of line. A
// citation may name the file relative to the repository or by a suffix.
func (c *corpus) cites(file string, line int) bool {
	for f, lines := range c.refs {
		if f != file && !strings.HasSuffix(file, "/"+f) && !strings.HasSuffix(f, "/"+file) {
			continue
		}
		for _, n := range lines {
			if n >= line-3 && n <= line+3 {
				return true
			}
		}
	}
	return false
}

// names reports whether an output contains the word w (identifier
// boundaries), optionally only in an output that also contains also.
func (c *corpus) names(w, also string) bool {
	if w == "" {
		return false
	}
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(w) + `($|[^A-Za-z0-9_])`)
	for _, t := range c.texts {
		if re.MatchString(t) && (also == "" || strings.Contains(t, also)) {
			return true
		}
	}
	return false
}

func pos(file string, line int) string { return fmt.Sprintf("%s:%d", file, line) }

// Check computes the missing units of an output directory.
func Check(out string) (*Result, error) {
	led, err := ledger.Load(filepath.Join(out, "coverage-ledger.json"))
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(out, "inventory.json"))
	if err != nil {
		return nil, err
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("inventory.json: %w", err)
	}
	c, idx, err := loadOutputs(out)
	if err != nil {
		return nil, err
	}
	saved := map[string]bool{}
	for _, e := range idx.Agents {
		if e.Status == "done" && e.File != "" {
			saved[e.ID] = true
		}
	}
	res := &Result{SchemaVersion: "1", MissingUnits: []Item{}, Counts: map[string]int{}, Outputs: len(c.texts)}
	listed := map[string]bool{}
	addItem := func(it Item) {
		if it.Kind != "unit-open" && it.Kind != "unit-no-output" && it.Unit != "" && listed[it.Unit] {
			return // the unit is already listed as open
		}
		if it.Unit != "" {
			listed[it.Unit] = true
		}
		it.Source = "tool"
		res.MissingUnits = append(res.MissingUnits, it)
		res.Counts[it.Kind]++
	}
	firstLens := func(u ledger.Unit) string {
		for _, l := range u.Lenses {
			if l != "V" {
				return l
			}
		}
		if len(u.Lenses) > 0 {
			return u.Lenses[0]
		}
		return ""
	}
	unitBy := map[string]ledger.Unit{} // kind + subject -> first unit
	for _, u := range led.Units {
		k := u.Kind + "\x00" + u.Subject
		if _, ok := unitBy[k]; !ok {
			unitBy[k] = u
		}
		switch u.Status {
		case "planned", "in_progress":
			addItem(Item{ID: u.ID, Kind: "unit-open", Why: "ledger unit still " + u.Status + ": no agent examined it", Lens: firstLens(u), Path: first(u.Paths), Unit: u.ID})
		case "covered", "candidate":
			ok := false
			for _, a := range u.AgentIDs {
				ok = ok || saved[a]
			}
			if !ok {
				addItem(Item{ID: u.ID, Kind: "unit-no-output", Why: "ledger unit is " + u.Status + " but none of its agents (" + strings.Join(u.AgentIDs, ", ") + ") has a saved output", Lens: firstLens(u), Path: first(u.Paths), Unit: u.ID})
			}
		}
	}
	unitFor := func(kind, subject string) string {
		if u, ok := unitBy[kind+"\x00"+subject]; ok {
			return u.ID
		}
		return ""
	}
	hintUnit := func(id string) string {
		for _, u := range led.Units {
			if u.Kind == "hint" && strings.HasPrefix(u.Subject, id+" ") {
				return u.ID
			}
		}
		return ""
	}
	addCmd := func(kind, subject, class, lens, at string) string {
		return fmt.Sprintf("ledger add --out %s --kind %s --subject %q --class %s --lens %s --path %s --notes \"critic-check\"", out, kind, subject, class, lens, at)
	}
	// hint sites
	for _, h := range inv.Hints {
		if h.InTest || c.cites(h.Pos.File, h.Pos.Line) || c.names(h.HintFunc, h.Pos.File) || c.names(h.HintFunc, path.Base(h.Pos.File)) {
			continue
		}
		u := hintUnit(h.ID)
		it := Item{ID: h.ID + " " + h.HintFunc + " @ " + pos(h.Pos.File, h.Pos.Line), Kind: "hint", Lens: "C1", Path: pos(h.Pos.File, h.Pos.Line), Unit: u,
			Why: "no agent output cites this hint call site or names its hint function"}
		if u == "" {
			it.Add = addCmd("hint", it.ID, "hint-soundness", "C1", it.Path)
		}
		addItem(it)
	}
	// public inputs of production circuits
	for _, ci := range inv.Circuits {
		if ci.InTest || ci.Witness == nil {
			continue
		}
		for _, g := range ci.Witness.Public {
			leaf := g.GoPath
			if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
				leaf = leaf[i+1:]
			}
			if c.cites(g.Decl.File, g.Decl.Line) || c.names(ci.Name+"."+g.GoPath, "") || c.names(g.GoPath, path.Base(ci.Decl.File)) || c.names(leaf, ci.Name) {
				continue
			}
			subject := ci.Name + "." + g.Name
			u := unitFor("public-input", subject)
			it := Item{ID: subject, Kind: "public-input", Lens: "I1", Path: pos(g.Decl.File, g.Decl.Line), Unit: u,
				Why: "no agent output names this public input or cites its declaration"}
			if u == "" {
				it.Add = addCmd("public-input", subject, "public-input-binding", "I1", it.Path)
			}
			addItem(it)
		}
	}
	if sol := inv.Contracts; sol != nil {
		fn := func(kind, contract, function, file string, line int, lens, class, why string) {
			if c.cites(file, line) || c.names(contract+"."+function, "") || c.names(function, path.Base(file)) {
				return
			}
			subject := contract + "." + function
			u := ""
			for _, x := range led.Units {
				if x.Kind == "contract-fn" && x.Subject == subject && x.Class == class {
					u = x.ID
				}
			}
			if u == "" {
				u = unitFor("contract-fn", subject)
			}
			it := Item{ID: subject + " @ " + pos(file, line), Kind: kind, Lens: lens, Path: pos(file, line), Unit: u, Why: why}
			if u == "" {
				it.Add = addCmd("contract-fn", subject, class, lens, it.Path)
			}
			addItem(it)
		}
		for _, v := range sol.VerifyCalls {
			fn("verify-call", v.Contract, v.Function, v.File, v.Line, "I1", "public-input-binding", "no agent output cites this verifier call or names its function")
		}
		for _, p := range sol.Privileged {
			fn("privileged", p.Contract, p.Function, p.File, p.Line, "T1", "trusted-party", "no agent output names this privileged function (gate "+p.Gate+", party "+p.Party+")")
		}
		for _, e := range sol.EntryPoints {
			fn("entry-point", e.Contract, e.Function, e.File, e.Line, "S1", "contract-review", "no agent output names this entry point")
		}
	}
	for _, g := range inv.Gadgets {
		if g.InTest || c.cites(g.Pos.File, g.Pos.Line) || c.names(g.Name, "") {
			continue
		}
		u := unitFor("gadget", g.Name)
		it := Item{ID: g.Name, Kind: "gadget", Lens: "L1", Path: pos(g.Pos.File, g.Pos.Line), Unit: u, Why: "no agent output names this exported gadget"}
		if u == "" {
			it.Add = addCmd("gadget", g.Name, "doc-contract", "L1", it.Path)
		}
		addItem(it)
	}
	return res, nil
}

func first(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

// Undecided lists the items of the saved check (critic-check.json) that
// still need a decision. An item is decided when a fresh check no longer
// reports it (an agent output now cites it, or its unit was examined), or
// when its ledger unit (or a unit added for it with `ledger add`) is
// deferred, blocked, not applicable or out of scope with a reason, was
// re-examined in a targeted wave (wave > 0), or carries a note with
// "dismissed" and the reason.
func Undecided(out string) ([]Item, error) {
	b, err := os.ReadFile(filepath.Join(out, File))
	if err != nil {
		return nil, fmt.Errorf("%s: %w (run critic-check first)", File, err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", File, err)
	}
	fresh, err := Check(out)
	if err != nil {
		return nil, err
	}
	still := map[string]bool{}
	for _, it := range fresh.MissingUnits {
		still[it.Kind+"\x00"+it.ID] = true
	}
	led, err := ledger.Load(filepath.Join(out, "coverage-ledger.json"))
	if err != nil {
		return nil, err
	}
	decided := func(u ledger.Unit) bool {
		switch u.Status {
		case "deferred", "blocked", "not_applicable", "out_of_scope":
			return strings.TrimSpace(u.Reason) != ""
		}
		return u.Wave > 0 || strings.Contains(strings.ToLower(u.Notes), "dismissed")
	}
	var open []Item
	for _, it := range r.MissingUnits {
		if !still[it.Kind+"\x00"+it.ID] {
			continue
		}
		ok := false
		for _, u := range led.Units {
			if (it.Unit != "" && u.ID == it.Unit) || (it.Unit == "" && u.Subject != "" && strings.Contains(u.Notes, "critic-check") && strings.HasPrefix(it.ID, u.Subject)) {
				ok = ok || decided(u)
			}
		}
		if !ok {
			open = append(open, it)
		}
	}
	return open, nil
}
