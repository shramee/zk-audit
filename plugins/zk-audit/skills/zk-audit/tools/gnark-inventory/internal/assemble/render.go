package assemble

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

const disclaimer = `> This review is a time-boxed, best-effort search for bugs by an automated
> agent. It is not a guarantee of security. Absence of a finding is not
> evidence of absence of bugs.
`

// maxQuote caps the number of source lines quoted per finding.
const maxQuote = 30

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", " ")
}

func inline(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " ") }

func code(s string) string {
	if s == "" {
		return ""
	}
	tick := "`"
	for strings.Contains(s, tick) {
		tick += "`"
	}
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return tick + pad + inline(s) + pad + tick
}

// fence returns a code fence longer than any backtick run in body.
func fence(body string) string {
	f := "```"
	for strings.Contains(body, f) {
		f += "`"
	}
	return f
}

func locStr(l Location) string {
	if l.EndLine > l.Line {
		return fmt.Sprintf("%s:%d-%d", l.File, l.Line, l.EndLine)
	}
	return fmt.Sprintf("%s:%d", l.File, l.Line)
}

// agentOrder sorts agent ids C*, I*, T*, PR*, V-*, G*, A*, F*, then
// anything else.
func agentOrder(ids []string) []string {
	group := func(s string) int {
		for i, p := range []string{"C", "I", "S", "T", "PR", "V-", "G", "A", "F"} {
			if p == "V-" {
				if strings.HasPrefix(s, p) {
					return i
				}
				continue
			}
			if strings.HasPrefix(s, p) && len(s) > len(p) && s[len(p)] >= '0' && s[len(p)] <= '9' {
				return i
			}
		}
		return 9
	}
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool {
		if gi, gj := group(out[i]), group(out[j]); gi != gj {
			return gi < gj
		}
		return out[i] < out[j]
	})
	return out
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func render(in *input) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	title := "# ZK security review — " + repoName(in.f.Repo)
	if c := in.f.Commit; c != "" {
		if len(c) > 7 {
			c = c[:7]
		}
		title += " @ " + c
	}
	w("%s\n\n", title)
	w("Rendered by `gnark-inventory assemble` from `findings.json` and `coverage-ledger.json`. Coverage statements come only from the ledger.\n\n")

	confirmed := in.byVerdict("confirmed")
	needs := in.needsOpen()
	leads := in.byVerdict("lead")
	rejected := in.byVerdict("rejected")
	sortRanked(confirmed)
	sortRanked(needs)

	in.writeScope(&b)
	in.writePosture(&b, confirmed, needs, leads, rejected)

	w("## 3. Findings\n\n")
	if len(confirmed) == 0 {
		w("No confirmed findings in the examined units. Section %d lists what was and was not examined.\n\n", secCoverage)
	} else {
		w("| # | Title | Severity | Confidence | Evidence | Detected by |\n|---|---|---|---|---|---|\n")
		for i, r := range confirmed {
			w("| %d | %s | %s | %d | %s | %s |\n", i+1, cell(titleOf(r)), r.Severity, conf(r), r.Evidence, cell(strings.Join(agentOrder(r.DetectedBy), ", ")))
		}
		w("\n")
	}

	w("## 4. Finding details\n\n")
	if len(confirmed) == 0 {
		w("None.\n\n")
	}
	for i, r := range confirmed {
		in.writeDetail(&b, i+1, r)
	}

	w("## 5. Leads\n\n")
	if len(leads) == 0 {
		w("None.\n\n")
	} else {
		w("Trails worth manual work. No severity, no fix.\n\n")
		sort.SliceStable(leads, func(i, j int) bool {
			a, c := leads[i], leads[j]
			if a.Location.File != c.Location.File {
				return a.Location.File < c.Location.File
			}
			if a.Location.Line != c.Location.Line {
				return a.Location.Line < c.Location.Line
			}
			return a.Fingerprint < c.Fingerprint
		})
		for _, r := range leads {
			w("- **%s** — %s · %s · detected by %s — %s Smells: %s. Unverified: %s\n",
				inline(titleOf(r)), code(r.Location.Scope), code(locStr(r.Location)), strings.Join(agentOrder(r.DetectedBy), ", "),
				endSentence(inline(r.Description)), inline(strings.Join(r.CodeSmells, "; ")), endSentence(inline(r.Unverified)))
			if r.PoC != nil {
				w("  PoC kept: %s\n", pocLine(r.PoC))
			}
		}
		w("\n")
	}

	w("## 6. Needs validation\n\n")
	if n := len(in.accepted()); n > 0 {
		w("%s accepted in `zk-audit.md` %s listed in section %d, not here.\n\n", plural(n, "trusted-party risk"), map[bool]string{true: "is", false: "are"}[n == 1], secTrusted)
	}
	if len(needs) == 0 {
		w("None.\n\n")
	} else {
		w("| Item | Severity | Confidence | Blockers | How to validate |\n|---|---|---|---|---|\n")
		for _, r := range needs {
			w("| **%s** · %s | %s | %d | %s | %s |\n", cell(titleOf(r)), cell(code(locStr(r.Location))), r.Severity, conf(r), cell(strings.Join(r.Blockers, "; ")), cell(r.ValidationPlan))
		}
		w("\n")
		for _, r := range needs {
			if r.PoC != nil {
				w("- PoC kept for **%s**: %s\n", inline(titleOf(r)), pocLine(r.PoC))
			}
		}
	}

	in.writeTrusted(&b)
	in.writePrivacy(&b)

	w("## %d. Hardening notes\n\n", secHardening)
	if len(in.f.Hardening) == 0 {
		w("None recorded.\n\n")
	} else {
		for _, h := range in.f.Hardening {
			w("- **%s**", inline(h.Title))
			if h.Location != nil {
				w(" — %s", code(locStr(*h.Location)))
			}
			if h.Detail != "" {
				w(" — %s", inline(h.Detail))
			}
			w("\n")
		}
		w("\n")
	}

	in.writeCoverage(&b, len(rejected))
	in.writeNotCovered(&b)
	w("%s", disclaimer)
	return b.String()
}

func endSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "?") || strings.HasSuffix(s, "!") {
		return s
	}
	return s + "."
}

func titleOf(r *Record) string {
	switch {
	case r.RunTag != "" && r.Seen != nil:
		return fmt.Sprintf("%s [%s · seen in %d/%d passes]", r.Title, r.RunTag, r.Seen.Passes, r.Seen.Of)
	case r.RunTag != "":
		return r.Title + " [" + r.RunTag + "]"
	}
	return r.Title
}

func (in *input) writeScope(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## 1. Scope\n\n| | |\n|---|---|\n")
	w("| Profile | %s |\n", in.f.Profile)
	w("| Run | %s |\n", in.f.RunID)
	commit := "not recorded"
	if in.f.Commit != "" {
		commit = code(in.f.Commit)
	}
	w("| Commit | %s |\n", commit)

	var files []string
	for _, u := range in.l.Units {
		// candidate units were read too; they only lack a closed judgment
		if u.Status == "covered" || u.Status == "candidate" {
			files = append(files, u.ReviewedPaths...)
		}
	}
	files = uniq(files)
	sort.Strings(files)
	if len(files) == 0 {
		w("| Files reviewed | none recorded in the ledger |\n")
	} else {
		var cs []string
		for _, f := range files {
			cs = append(cs, code(f))
		}
		w("| Files reviewed | %s |\n", cell(strings.Join(cs, " · ")))
	}

	if in.s == nil {
		w("| Stack | not recorded (no stack.json) |\n")
	} else {
		w("| Stack | %s |\n", cell(in.s.Line()))
		var vs []string
		for _, m := range in.s.GoModules {
			var p []string
			if m.Gnark != "" {
				p = append(p, "gnark "+m.Gnark)
			}
			if m.GnarkLocal != "" {
				p = append(p, "gnark replaced by "+m.GnarkLocal)
			}
			if m.GnarkCrypto != "" {
				p = append(p, "gnark-crypto "+m.GnarkCrypto)
			}
			if m.Go != "" {
				p = append(p, "go "+m.Go)
			}
			if len(p) > 0 {
				vs = append(vs, code(m.Path)+": "+strings.Join(p, ", "))
			}
		}
		if len(vs) == 0 {
			vs = []string{"no gnark module"}
		}
		w("| Versions | %s |\n", cell(strings.Join(vs, " · ")))
		if len(in.s.Gnark.Advisories) == 0 {
			w("| Advisories | none matched the pinned gnark version |\n")
		} else {
			var as []string
			for _, a := range in.s.Gnark.Advisories {
				s := fmt.Sprintf("%s (%s, fixed %s", a.ID, a.Severity, a.Fixed)
				if a.Status != "affected" {
					s += ", " + strings.ReplaceAll(a.Status, "_", " ")
				}
				as = append(as, s+")")
			}
			w("| Advisories | %s |\n", cell(strings.Join(as, " · ")))
		}
	}

	if c := in.f.Companions; c == nil {
		w("| Companions | not recorded |\n")
	} else {
		var cs []string
		for _, p := range c.Present {
			cs = append(cs, "✔ "+p)
		}
		for _, m := range c.Missing {
			cs = append(cs, "✖ "+m)
		}
		if len(cs) == 0 {
			cs = []string{"none"}
		}
		w("| Companions | %s |\n", cell(strings.Join(cs, " · ")))
	}

	var agents []string
	for _, u := range in.l.Units {
		agents = append(agents, u.AgentIDs...)
	}
	for _, r := range in.f.Records {
		agents = append(agents, r.DetectedBy...)
	}
	var other []string
	known := agents[:0]
	for _, a := range uniq(agents) {
		if profile.Load().AgentKnown(a) {
			known = append(known, a)
		} else {
			other = append(other, a)
		}
	}
	agents = agentOrder(known)
	if len(agents) == 0 {
		w("| Agents | none recorded |\n")
	} else {
		w("| Agents | %s |\n", cell(strings.Join(agents, ", ")))
	}
	if len(other) > 0 {
		sort.Strings(other)
		w("| Other sources | %s |\n", cell(strings.Join(other, ", ")))
	}

	oos := append([]string(nil), in.f.OutOfScope...)
	n := 0
	for _, u := range in.l.Units {
		if u.Status == "out_of_scope" {
			n++
		}
	}
	if n > 0 {
		oos = append(oos, plural(n, "ledger unit")+fmt.Sprintf(" marked out_of_scope (section %d)", secCoverage))
	}
	if len(oos) == 0 {
		w("| Out of scope | none recorded |\n\n")
	} else {
		w("| Out of scope | %s |\n\n", cell(strings.Join(oos, " · ")))
	}
}

func (in *input) writePosture(b *strings.Builder, confirmed, needs, leads, rejected []*Record) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## 2. Posture\n\n")
	if in.f.Posture != "" {
		w("%s\n\n", strings.TrimSpace(in.f.Posture))
	} else {
		w("_No posture summary was recorded in `findings.json`._\n\n")
	}
	bySev := map[string]int{}
	for _, r := range confirmed {
		bySev[r.Severity]++
	}
	var sev []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			sev = append(sev, fmt.Sprintf("%d %s", bySev[s], s))
		}
	}
	line := fmt.Sprintf("Totals: %d confirmed", len(confirmed))
	if len(sev) > 0 {
		line += " (" + strings.Join(sev, ", ") + ")"
	}
	ex, app := in.examined()
	line += fmt.Sprintf(" · %d needs validation", len(needs))
	if n := len(in.accepted()); n > 0 {
		line += " · " + plural(n, "accepted risk")
	}
	line += fmt.Sprintf(" · %s · %d rejected. Ledger: %d of %s examined.", plural(len(leads), "lead"), len(rejected), ex, plural(app, "applicable unit"))
	w("%s\n\n", line)
	if len(confirmed) == 0 {
		if in.f.NoFindings {
			w("The run recorded no findings: %s\n\n", endSentence(inline(in.f.NoFindingsReason)))
		}
		w("The absence of confirmed findings does not mean the code is free of bugs. Only the units listed as examined in section %d were reviewed.\n\n", secCoverage)
	}
}

func (in *input) writeDetail(b *strings.Builder, n int, r *Record) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("### %d. %s\n\n", n, inline(titleOf(r)))
	meta := fmt.Sprintf("%s · %s · severity **%s** · confidence %d · evidence **%s** · detected by %s",
		code(r.Location.Scope), code(locStr(r.Location)), r.Severity, conf(r), r.Evidence, strings.Join(agentOrder(r.DetectedBy), ", "))
	if len(r.VectorIDs) > 0 {
		meta += " · vectors " + strings.Join(r.VectorIDs, ", ")
	}
	if r.Calibration != "" {
		meta += " · calibration " + r.Calibration
	}
	w("%s\n\n", meta)
	if len(r.RelatedLocations) > 0 {
		var ls []string
		for _, l := range r.RelatedLocations {
			ls = append(ls, code(l.Scope)+" "+code(locStr(l)))
		}
		w("Also at: %s\n\n", strings.Join(ls, " · "))
	}
	w("**Description.** %s\n\n", inline(r.Description))
	label := "Code"
	if r.Layer == "circuit" {
		label = "Constraint"
	}
	if q, lang, ok := in.quote(r.Location); ok {
		f := fence(q)
		w("**%s.** %s\n\n%s%s\n%s\n%s\n\n", label, code(locStr(r.Location)), f, lang, q, f)
	} else {
		w("**%s.** %s (source not available to the assembler).\n\n", label, code(locStr(r.Location)))
	}
	w("**Attack witness.** %s\n\n", inline(r.Proof))
	w("**Impact.** %s\n\n", inline(r.Impact))
	if r.Refuter != nil && r.Refuter.Verdict == "not_exploitable" && r.Gates != nil {
		w("**Gates.** executes: %s · reachable: %s · unprivileged: %s · impact: %s\n\n",
			inline(r.Gates.Executes), inline(r.Gates.Reachable), inline(r.Gates.Unprivileged), inline(r.Gates.Impact))
	}
	if r.PoC != nil {
		w("**PoC.** %s\n\n", pocLine(r.PoC))
		if ex := strings.TrimRight(r.PoC.OutputExcerpt, "\n"); ex != "" {
			lines := strings.Split(ex, "\n")
			if len(lines) > maxQuote {
				lines = lines[len(lines)-maxQuote:]
			}
			ex = strings.Join(lines, "\n")
			f := fence(ex)
			w("%stext\n%s\n%s\n\n", f, ex, f)
		}
	} else {
		w("**PoC.** none; evidence **%s**.\n\n", r.Evidence)
	}
	if r.Fix != nil {
		w("**Fix.** %s\n\n", inline(r.Fix.Summary))
		for i, o := range r.Fix.Options {
			d := strings.TrimRight(o.Diff, "\n")
			f := fence(d)
			w("Option %s — %s\n\n%sdiff\n%s\n%s\n\n", optionName(i), inline(reOptionPrefix.ReplaceAllString(o.Label, "")), f, d, f)
		}
	}
	if len(r.Chain) > 0 {
		var cs []string
		for _, c := range r.Chain {
			cs = append(cs, code(c))
		}
		w("**Chain.** %s\n\n", strings.Join(cs, " → "))
	}
	if r.Refuter != nil {
		by := ""
		if r.Refuter.By != "" {
			by = " (by " + inline(r.Refuter.By) + ")"
		}
		var split []string
		if r.Refuter.Mechanism != "" {
			split = append(split, "mechanism "+r.Refuter.Mechanism)
		}
		if r.Refuter.Impact != "" {
			split = append(split, "impact "+r.Refuter.Impact)
		}
		verdict := strings.ReplaceAll(r.Refuter.Verdict, "_", " ")
		if len(split) > 0 {
			verdict += " (" + strings.Join(split, ", ") + ")"
		}
		w("**Refuter.** %s — %s%s\n\n", verdict, endSentence(inline(r.Refuter.Reasoning)), by)
	} else {
		w("**Refuter.** not run.\n\n")
	}
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// reOptionPrefix matches a label that already starts with "Option A —", which
// the renderer adds itself.
var reOptionPrefix = regexp.MustCompile(`^\s*(?i:option)\s+[A-Z0-9]+\s*[—:.-]+\s*`)

func optionName(i int) string {
	if i < 26 {
		return string(rune('A' + i))
	}
	return fmt.Sprint(i + 1)
}

// open opens a repo-relative regular file of the audited tree. It refuses
// absolute paths and paths with "..", resolves symlinks in both the root and
// the file, and refuses a file whose real path leaves the real root (a
// symlink in the repository pointing at ~/.ssh/id_rsa is never quoted).
func (in *input) open(file string) (*os.File, bool) {
	if in.repo == "" || file == "" || filepath.IsAbs(file) || strings.HasPrefix(filepath.Clean(filepath.FromSlash(file)), "..") {
		return nil, false
	}
	root, err := filepath.EvalSymlinks(in.repo)
	if err != nil {
		return nil, false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return nil, false
	}
	if rel, err := filepath.Rel(root, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, false
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, false
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, false
	}
	return f, true
}

// lineCount returns the number of lines of a repo-relative file.
func (in *input) lineCount(file string) (int, bool) {
	f, ok := in.open(file)
	if !ok {
		return 0, false
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n++
	}
	return n, true
}

// quote returns the lines of l from the audited repository, verbatim.
func (in *input) quote(l Location) (string, string, bool) {
	f, ok := in.open(l.File)
	if !ok {
		return "", "", false
	}
	defer f.Close()
	end := l.EndLine
	if end < l.Line {
		end = l.Line
	}
	truncated := false
	if end-l.Line+1 > maxQuote {
		end = l.Line + maxQuote - 1
		truncated = true
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for i := 1; sc.Scan(); i++ {
		if i > end {
			break
		}
		if i >= l.Line {
			lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
		}
	}
	if len(lines) == 0 {
		return "", "", false
	}
	if truncated {
		lines = append(lines, fmt.Sprintf("// … truncated after %d lines", maxQuote))
	}
	lang := ""
	switch strings.ToLower(filepath.Ext(l.File)) {
	case ".go":
		lang = "go"
	case ".sol":
		lang = "solidity"
	}
	return strings.Join(lines, "\n"), lang, true
}

var statuses = []string{"planned", "in_progress", "covered", "candidate", "deferred", "blocked", "not_applicable", "out_of_scope"}
var kinds = []string{"circuit", "hint", "public-input", "contract-fn", "verifier", "role", "setup", "prover", "dependency"}

func (in *input) writeCoverage(b *strings.Builder, rejected int) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	w("## %d. Coverage\n\n", secCoverage)
	counts := map[string]map[string]int{}
	total := map[string]int{}
	for _, u := range in.l.Units {
		if counts[u.Kind] == nil {
			counts[u.Kind] = map[string]int{}
		}
		counts[u.Kind][u.Status]++
		total[u.Status]++
	}
	w("| Kind | Units | planned | in progress | covered | candidate | deferred | blocked | not applicable | out of scope |\n|---|---|---|---|---|---|---|---|---|---|\n")
	row := func(name string, c map[string]int, n int) {
		w("| %s | %d", name, n)
		for _, s := range statuses {
			w(" | %d", c[s])
		}
		w(" |\n")
	}
	for _, k := range kinds {
		if c := counts[k]; c != nil {
			n := 0
			for _, v := range c {
				n += v
			}
			row(k, c, n)
		}
	}
	row("**total**", total, len(in.l.Units))
	ex, app := in.examined()
	pct := 0
	if app > 0 {
		pct = ex * 100 / app
	}
	w("\nExamined (covered): %d of %d applicable units (%d%%).\n\n", ex, app, pct)

	var open, skipped []Unit
	for _, u := range in.l.Units {
		switch u.Status {
		case "planned", "in_progress", "candidate", "deferred", "blocked":
			open = append(open, u)
		case "not_applicable", "out_of_scope":
			skipped = append(skipped, u)
		}
	}
	reason := func(u Unit) string {
		if u.Status == "candidate" && strings.TrimSpace(u.Reason) == "" {
			return "raised " + strings.Join(u.ResultFingerprints, ", ") + "; not closed after judging"
		}
		if strings.TrimSpace(u.Reason) == "" {
			return "no reason recorded"
		}
		return inline(u.Reason)
	}
	if len(open) == 0 {
		w("Units not examined: none.\n\n")
	} else {
		w("Units not examined:\n\n")
		for _, u := range open {
			w("- %s — %s — %s\n", code(u.ID), strings.ReplaceAll(u.Status, "_", " "), reason(u))
		}
		w("\n")
	}
	if len(skipped) > 0 {
		w("Units not applicable or out of scope:\n\n")
		for _, u := range skipped {
			w("- %s — %s — %s\n", code(u.ID), strings.ReplaceAll(u.Status, "_", " "), reason(u))
		}
		w("\n")
	}
	w("Rejected candidates: %d (kept in `findings.json` so a later run does not raise them again).\n\n", rejected)
	if c := in.f.Companions; c == nil {
		w("Companions: not recorded.\n\n")
	} else if len(c.Missing) == 0 {
		w("Companions not available: none.\n\n")
	} else {
		w("Companions not available: %s. Their areas were covered only by the embedded fallbacks.\n\n", strings.Join(c.Missing, ", "))
	}
	if in.inv == nil {
		w("Inventory load mode: not recorded (no `inventory.json`).\n\n")
	} else {
		w("Inventory load mode: `%s` (%s).", in.inv.LoadMode, plural(len(in.inv.LoadErrors), "load error"))
		if in.inv.LoadMode != "types" {
			w(" Items marked unresolved in `inventory.md` were not type-checked.")
		}
		w("\n\n")
		for i, e := range in.inv.LoadErrors {
			if i == 5 {
				w("- … %d more in `inventory.json`\n", len(in.inv.LoadErrors)-5)
				break
			}
			w("- %s\n", inline(e))
		}
		if len(in.inv.LoadErrors) > 0 {
			w("\n")
		}
	}
}

// pocLine describes a PoC: file, command, result, and which property it
// breaks.
func pocLine(p *PoC) string {
	res := strings.ReplaceAll(p.Result, "_", " ")
	if p.Demonstrates != "" {
		res += " (" + p.Demonstrates + ")"
	}
	return fmt.Sprintf("%s — %s → %s.", code(p.Path), code(p.Command), res)
}
