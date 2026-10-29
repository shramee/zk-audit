package assemble

import (
	"fmt"
	"strings"
)

// gadgetCount is the number of non-test exported gadgets in inventory.json.
func (in *input) gadgetCount() int {
	if in.inv == nil {
		return 0
	}
	n := 0
	for _, g := range in.inv.Gadgets {
		if !g.InTest {
			n++
		}
	}
	return n
}

// writeGadgets renders the gadget contract table (library mode): per
// exported gadget, what its doc promises and requires, the inventory's doc
// checks, the status of its doc-contract ledger unit and the records that
// unit produced.
func (in *input) writeGadgets(b *strings.Builder) {
	if in.gadgetCount() == 0 {
		return
	}
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	units := map[string]Unit{}
	for _, u := range in.l.Units {
		if u.Kind == "gadget" && u.Class == "doc-contract" {
			units[u.Subject] = u
		}
	}
	recs := map[string]*Record{}
	for i := range in.f.Records {
		recs[in.f.Records[i].Fingerprint] = &in.f.Records[i]
	}
	w("### Gadget contracts\n\n")
	w("One row per exported gadget (`inventory.json` `gadgets`). Promises and preconditions are the doc comment's sentences by property; doc checks are the inventory's syntactic notes, not verdicts; the unit is the gadget's `doc-contract` ledger unit (lens L1).\n\n")
	w("| Id | Gadget | Location | Doc promises | Doc preconditions | Doc checks | Doc-contract unit | Records |\n|---|---|---|---|---|---|---|---|\n")
	for _, g := range in.inv.Gadgets {
		if g.InTest {
			continue
		}
		claims := func(cs []InvClaim) string {
			var ks []string
			seen := map[string]bool{}
			for _, c := range cs {
				for _, k := range c.Kinds {
					if !seen[k] {
						seen[k] = true
						ks = append(ks, k)
					}
				}
			}
			if len(ks) == 0 {
				return "–"
			}
			return strings.Join(ks, ", ")
		}
		var checks []string
		for _, c := range g.Checks {
			checks = append(checks, c.Kind)
		}
		status, rs := "no unit", "–"
		if u, ok := units[g.Name]; ok {
			status = strings.ReplaceAll(u.Status, "_", " ")
			var parts []string
			for _, fp := range u.ResultFingerprints {
				if r := recs[fp]; r != nil {
					sev := r.Severity
					if sev == "" {
						sev = "–"
					}
					parts = append(parts, fmt.Sprintf("%s (%s, %s)", inline(titleOf(r)), r.Verdict, sev))
				}
			}
			if len(parts) > 0 {
				rs = strings.Join(parts, "; ")
			}
		}
		chk := "–"
		if len(checks) > 0 {
			chk = strings.Join(checks, ", ")
		}
		w("| %s | %s | %s | %s | %s | %s | %s | %s |\n", g.ID, code(g.Name), code(fmt.Sprintf("%s:%d", g.Pos.File, g.Pos.Line)), claims(g.Promises), claims(g.Preconds), chk, status, cell(rs))
	}
	w("\n")
}
