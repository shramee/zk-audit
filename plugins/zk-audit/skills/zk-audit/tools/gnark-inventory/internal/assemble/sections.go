package assemble

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Section numbers after the fixed sections 1-6.
const (
	secTrusted    = 7
	secPrivacy    = 8
	secHardening  = 9
	secCoverage   = 10
	secNotCovered = 11
)

// notCovered is the fixed part of the "Not covered" section: what the skill
// never examines, whatever the profile.
var notCovered = []string{
	"gnark itself: its backends, gnark-crypto and the internals of std, beyond matching the pinned version against known advisories and checking the preconditions of the gadgets the circuits call;",
	"circuits written for other frameworks (Circom, Noir, Halo2), which are routed to companion skills or checked against the generic vectors only;",
	"cryptographic assumptions: hash, curve and pairing security, the soundness of the proof system, and trusted-setup ceremony transcripts;",
	"deployed state and infrastructure outside the repository: bytecode, verifying keys and owners on chain, servers, key management, and relayers, indexers and frontends as operated;",
	"economic, governance and MEV attacks beyond the listed vectors;",
	"formal verification: no property is proven.",
}

// needsOpen lists needs_validation records that are not accepted risks,
// sorted like the findings table.
func (in *input) needsOpen() []*Record {
	var out []*Record
	for _, r := range in.byVerdict("needs_validation") {
		if r.Trust == nil || !r.Trust.Accepted {
			out = append(out, r)
		}
	}
	sortRanked(out)
	return out
}

// accepted lists records zk-audit.md accepts (trust.accepted).
func (in *input) accepted() []*Record {
	var out []*Record
	for i := range in.f.Records {
		r := &in.f.Records[i]
		if r.Trust != nil && r.Trust.Accepted && r.Verdict != "rejected" {
			out = append(out, r)
		}
	}
	return out
}

// classCount counts ledger units of a class and how many are covered.
func (in *input) classCount(class string) (covered, total int) {
	for _, u := range in.l.Units {
		if u.Class != class {
			continue
		}
		total++
		if u.Status == "covered" {
			covered++
		}
	}
	return covered, total
}

// lensOutside reports whether the run's profile is a defined profile that
// does not select the lens.
func (in *input) lensOutside(id string) bool {
	set := profile.Load()
	if _, ok := set.Profile(in.f.Profile); !ok {
		return false
	}
	l, ok := set.Lens(id)
	return ok && !l.In(in.f.Profile)
}

func (in *input) writeTrusted(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## %d. Trusted parties\n\n", secTrusted)
	var rs []*Record
	for i := range in.f.Records {
		r := &in.f.Records[i]
		if r.Trust != nil && r.Verdict != "rejected" {
			rs = append(rs, r)
		}
	}
	sortRanked(rs)
	if len(rs) == 0 && len(in.f.AcceptedRisks) == 0 {
		w("No trusted-party power was recorded.\n\n")
	} else {
		w("Powers that a trusted party holds over soundness, funds, liveness or privacy. Each is an assumption users carry, not a defect the code can fix alone.\n\n")
	}
	if len(rs) > 0 {
		w("| Party | Power | Breaks | Assumption | Status | Severity | Where |\n|---|---|---|---|---|---|---|\n")
		for _, r := range rs {
			t := r.Trust
			status := strings.ReplaceAll(r.Verdict, "_", " ")
			switch {
			case t.Accepted:
				status = "accepted risk (" + code(t.Source) + ")"
			case r.Verdict == "confirmed":
				status = "confirmed: unprivileged path"
			}
			sev := r.Severity
			if sev == "" {
				sev = "–"
			}
			assumption := t.Assumption
			if strings.TrimSpace(t.Mitigation) != "" {
				assumption = endSentence(assumption) + " Mitigation: " + t.Mitigation
			}
			w("| %s (%s) | %s | %s | %s | %s | %s | %s %s |\n", cell(t.Party), t.Role, cell(t.Power), strings.Join(t.Breaks, ", "),
				cell(assumption), cell(status), sev, cell(inline(titleOf(r))), cell(code(locStr(r.Location))))
		}
		w("\n")
	}
	if len(in.f.AcceptedRisks) > 0 {
		w("Accepted in `zk-audit.md` without a record:\n\n")
		for _, a := range in.f.AcceptedRisks {
			w("- **%s** — %s (%s)\n", inline(a.Party), endSentence(inline(a.Risk)), code(a.Source))
		}
		w("\n")
	}
	cov, tot := in.classCount("trusted-party")
	switch {
	case in.lensOutside("T1"):
		w("The trusted-party lens (T1) is not part of the `%s` profile.", in.f.Profile)
	case tot == 0:
		w("The ledger has no `trusted-party` unit: the inventory found no privileged function, role or setup site.")
	default:
		w("Trusted-party units examined: %d of %d (privileged functions, roles and setup sites; section %d lists the rest).", cov, tot, secCoverage)
	}
	w("\n\n")
}

// isPrivacy reports whether a record belongs in the Privacy section.
func isPrivacy(r *Record) bool {
	if r.Property == "privacy" {
		return true
	}
	for _, v := range r.VectorIDs {
		if strings.HasPrefix(v, "V-PR") {
			return true
		}
	}
	if r.Trust != nil {
		for _, x := range r.Trust.Breaks {
			if x == "privacy" {
				return true
			}
		}
	}
	return false
}

func (in *input) writePrivacy(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## %d. Privacy\n\n", secPrivacy)
	var rs []*Record
	for i := range in.f.Records {
		r := &in.f.Records[i]
		if r.Verdict != "rejected" && isPrivacy(r) {
			rs = append(rs, r)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool {
		vi, vj := verdictRank[rs[i].Verdict], verdictRank[rs[j].Verdict]
		if vi != vj {
			return vi < vj
		}
		return sevRank[rs[i].Severity] < sevRank[rs[j].Severity]
	})
	if len(rs) == 0 {
		w("No privacy finding was recorded.\n\n")
	} else {
		w("What the public inputs, calldata, events, operators or services reveal about values the protocol claims to hide.\n\n")
		w("| Item | Verdict | Severity | Where | Detected by |\n|---|---|---|---|---|\n")
		for _, r := range rs {
			sev := r.Severity
			if sev == "" {
				sev = "–"
			}
			status := strings.ReplaceAll(r.Verdict, "_", " ")
			if r.Trust != nil && r.Trust.Accepted {
				status = "accepted risk"
			}
			w("| %s | %s | %s | %s | %s |\n", cell(inline(titleOf(r))), status, sev, cell(code(locStr(r.Location))), cell(strings.Join(agentOrder(r.DetectedBy), ", ")))
		}
		w("\n")
	}
	cov, tot := in.classCount("privacy")
	switch {
	case in.lensOutside("PR1"):
		w("The privacy lens (PR1) is not part of the `%s` profile; privacy was examined only through other lenses' findings.", in.f.Profile)
	case tot == 0:
		w("The ledger has no `privacy` unit.")
	default:
		w("Privacy units examined: %d of %d (one per production circuit).", cov, tot)
	}
	w("\n\n")
}

var verdictRank = map[string]int{"confirmed": 0, "needs_validation": 1, "lead": 2, "rejected": 3}

func (in *input) writeNotCovered(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## %d. Not covered\n\n", secNotCovered)
	w("This review never examines:\n\n")
	for _, s := range notCovered {
		w("- %s\n", s)
	}
	w("\nIn this run:\n\n")
	set := profile.Load()
	if _, ok := set.Profile(in.f.Profile); ok {
		var out []string
		for _, l := range set.Lenses {
			if !l.In(in.f.Profile) && (l.When != "exported-gadgets" || in.gadgetCount() > 0) {
				out = append(out, l.ID)
			}
		}
		if len(out) == 0 {
			w("- every lens is part of the `%s` profile;\n", in.f.Profile)
		} else {
			w("- lenses not part of the `%s` profile: %s;\n", in.f.Profile, strings.Join(agentOrder(out), ", "))
		}
	} else {
		w("- the `%s` run has no fixed lens set; section 1 lists the agents that ran;\n", in.f.Profile)
	}
	open := 0
	for _, u := range in.l.Units {
		switch u.Status {
		case "planned", "in_progress", "candidate", "deferred", "blocked":
			open++
		}
	}
	_, app := in.examined()
	w("- ledger units not examined: %d of %d applicable (section %d);\n", open, app, secCoverage)
	if c := in.f.Companions; c == nil {
		w("- companions: not recorded.\n\n")
	} else if len(c.Missing) == 0 {
		w("- companions not available: none.\n\n")
	} else {
		w("- companions not available: %s.\n\n", strings.Join(c.Missing, ", "))
	}
}
