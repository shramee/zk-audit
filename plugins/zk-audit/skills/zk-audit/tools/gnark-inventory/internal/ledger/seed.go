// Package ledger seeds coverage-ledger.json from an inventory. Every unit
// starts as "planned"; agents and critics move units to other statuses.
package ledger

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Unit is one ledger unit (see schemas/ledger.schema.json).
type Unit struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Subject            string   `json:"subject"`
	Class              string   `json:"class"`
	Lenses             []string `json:"lenses"`
	Paths              []string `json:"paths"`
	Status             string   `json:"status"`
	AgentIDs           []string `json:"agent_ids"`
	ReviewedPaths      []string `json:"reviewed_paths"`
	ResultFingerprints []string `json:"result_fingerprints"`
	Wave               int      `json:"wave"`
	Reason             string   `json:"reason,omitempty"`
	Notes              string   `json:"notes,omitempty"`
}

// Ledger is the document.
type Ledger struct {
	SchemaVersion string `json:"schema_version"`
	Repo          string `json:"repo"`
	RunID         string `json:"run_id,omitempty"`
	Profile       string `json:"profile,omitempty"`
	GeneratedBy   string `json:"generated_by"`
	Units         []Unit `json:"units"`
}

// seeded lists, in profiles.json order, the classes a lens owns that the
// seeder creates one unit per subject of kind for ("circuit" or
// "contract-fn"), with the lenses listed on each unit.
func seeded(kind string) []struct {
	class  string
	lenses []string
} {
	var out []struct {
		class  string
		lenses []string
	}
	for _, l := range profile.Load().Lenses {
		if l.Ledger == nil || l.Ledger.Seed != kind {
			continue
		}
		for _, c := range l.Ledger.Classes {
			out = append(out, struct {
				class  string
				lenses []string
			}{c, append([]string{l.ID}, l.Ledger.With...)})
		}
	}
	return out
}

func safe(s string) string {
	s = strings.ReplaceAll(s, "|", "/")
	return strings.TrimSpace(s)
}

// Seed builds the ledger. stack may be nil.
func Seed(inv *inventory.Inventory, stack *detect.Stack, tool string) *Ledger {
	l := &Ledger{SchemaVersion: "1", Repo: inv.Repo, GeneratedBy: tool, Units: []Unit{}}
	add := func(kind, subject, class string, lenses []string, paths []string, notes string) {
		id := kind + ":" + safe(subject) + "|" + class
		for _, u := range l.Units {
			if u.ID == id {
				return
			}
		}
		if len(paths) == 0 {
			paths = []string{"?"}
		}
		l.Units = append(l.Units, Unit{
			ID: id, Kind: kind, Subject: subject, Class: class, Lenses: lenses, Paths: paths,
			Status: "planned", AgentIDs: []string{}, ReviewedPaths: []string{}, ResultFingerprints: []string{}, Notes: notes,
		})
	}
	pos := func(p inventory.Pos) string { return fmt.Sprintf("%s:%d", p.File, p.Line) }

	for _, c := range inv.Circuits {
		if c.InTest {
			continue
		}
		for _, cc := range seeded("circuit") {
			add("circuit", c.Name, cc.class, cc.lenses, []string{pos(c.Define)}, "")
		}
		for _, g := range c.Witness.Public {
			add("public-input", c.Name+"."+g.Name, "public-input-binding", []string{"I1", "G2"}, []string{pos(g.Decl)},
				fmt.Sprintf("index %s, %s leaves", g.StartExpr, lenStr(g.Len)))
		}
	}
	for _, h := range inv.Hints {
		if h.InTest {
			continue
		}
		note := "status from inventory: " + h.Status
		add("hint", h.ID+" "+h.HintFunc+" @ "+pos(h.Pos), "hint-soundness", []string{"C1", "A1"}, []string{pos(h.Pos)}, note)
	}
	if inv.Contracts != nil {
		for _, v := range inv.Contracts.Verifiers {
			add("verifier", v.Contract, "verifier-contract", []string{"I2"}, []string{fmt.Sprintf("%s:%d", v.File, v.Line)}, v.Kind)
		}
		fns := map[string]string{}
		for _, vc := range inv.Contracts.VerifyCalls {
			fns[vc.Contract+"."+vc.Function] = fmt.Sprintf("%s:%d", vc.File, vc.Line)
		}
		for _, sa := range inv.Contracts.StateAccess {
			if sa.Op == "write" || sa.Op == "delete" || sa.Op == "push" {
				k := sa.Contract + "." + sa.Function
				if _, ok := fns[k]; !ok {
					fns[k] = fmt.Sprintf("%s:%d", sa.File, sa.Line)
				}
			}
		}
		var keys []string
		for k := range fns {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, cc := range seeded("contract-fn") {
				add("contract-fn", k, cc.class, cc.lenses, []string{fns[k]}, "")
			}
		}
	}
	// trusted parties: one unit per privileged function, declared role and
	// production setup site, for each class seeded "privileged"
	if priv := seeded("privileged"); len(priv) > 0 {
		if inv.Contracts != nil {
			for _, p := range inv.Contracts.Privileged {
				for _, cc := range priv {
					add("contract-fn", p.Contract+"."+p.Function, cc.class, cc.lenses, []string{fmt.Sprintf("%s:%d", p.File, p.Line)},
						fmt.Sprintf("gate %s; party %s; powers %s", p.Gate, p.Party, strings.Join(p.Powers, ", ")))
				}
			}
			for _, r := range inv.Contracts.Roles {
				for _, cc := range priv {
					add("role", r.Contract+"."+r.Name, cc.class, cc.lenses, []string{fmt.Sprintf("%s:%d", r.File, r.Line)}, r.Kind+"; "+r.Source)
				}
			}
		}
		setup := map[string]string{}
		var setupFiles []string
		for _, f := range inv.Footguns {
			if f.InTest || f.ID != "FG-DEV-SETUP" {
				continue
			}
			if _, ok := setup[f.Pos.File]; !ok {
				setup[f.Pos.File] = pos(f.Pos)
				setupFiles = append(setupFiles, f.Pos.File)
			}
		}
		sort.Strings(setupFiles)
		for _, f := range setupFiles {
			for _, cc := range priv {
				add("setup", f, cc.class, cc.lenses, []string{setup[f]}, "who runs this setup, and are its keys the deployed ones?")
			}
		}
		// key and ceremony files, and MPC ceremony code, from the
		// provenance scan
		if p := inv.Provenance; p != nil && p.Ceremony != nil {
			for _, sc := range p.Ceremony.Setups {
				if sc.InTest || sc.Kind == "single-party" {
					continue // single-party sites come from FG-DEV-SETUP above
				}
				for _, cc := range priv {
					add("setup", sc.File, cc.class, cc.lenses, []string{fmt.Sprintf("%s:%d", sc.File, sc.Line)},
						sc.Kind+" setup code: how many independent contributors, is the transcript verified, and are its keys the deployed ones?")
				}
			}
			for _, a := range p.Ceremony.Artifacts {
				n := "contributions not recorded in the file"
				if a.Contributions >= 0 {
					n = fmt.Sprintf("%d contribution(s) recorded", a.Contributions)
				}
				for _, cc := range priv {
					add("setup", a.File, cc.class, cc.lenses, []string{a.File},
						a.Kind+", "+n+": who generated it, and is it the deployed key? (setup provenance: "+p.Ceremony.Verdict+")")
				}
			}
		}
	}
	// the ABI check's result on each checked call site's verifier-contract unit
	if p := inv.Provenance; p != nil && p.ABI != nil {
		for _, c := range p.ABI.Calls {
			if c.Status != "mismatch" {
				continue
			}
			var st []string
			for _, a := range c.Against {
				if a.Status != "match" && a.Status != "unknown" {
					st = append(st, a.Status+" vs "+a.Name)
				}
			}
			for i := range l.Units {
				u := &l.Units[i]
				if u.Kind == "contract-fn" && u.Subject == c.Caller && u.Class == "verifier-contract" {
					u.Notes = joinNotes(u.Notes, "ABI check ("+c.Site+"): "+strings.Join(st, "; "))
				}
			}
		}
		for _, v := range p.ABI.Verifiers {
			for i := range l.Units {
				u := &l.Units[i]
				if u.Kind == "verifier" && u.Subject == v.Verifier {
					u.Notes = joinNotes(u.Notes, "template check: "+v.Status+" ("+v.Detail+")")
				}
			}
		}
	}
	// prover-service: non-test files that touch backends or deserialization
	prover := map[string]bool{}
	for _, f := range inv.Footguns {
		if f.InTest {
			continue
		}
		switch f.ID {
		case "FG-DEV-SETUP", "FG-UNTRUSTED-DESERIALIZE", "FG-HASH-TO-FIELD":
			prover[f.Pos.File] = true
		}
	}
	var pf []string
	for f := range prover {
		pf = append(pf, f)
	}
	sort.Strings(pf)
	for _, f := range pf {
		add("prover", f, "prover-service", []string{"I4"}, []string{f}, "")
	}
	if stack != nil {
		for _, m := range stack.GoModules {
			if m.Gnark != "" || m.GnarkLocal != "" {
				add("dependency", path.Clean(m.Path)+" gnark "+m.Gnark, "gnark-version", []string{"I4"}, []string{m.Path}, "")
			}
		}
	}
	return l
}

func joinNotes(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func lenStr(n int) string {
	if n < 0 {
		return "dynamic"
	}
	return fmt.Sprint(n)
}
