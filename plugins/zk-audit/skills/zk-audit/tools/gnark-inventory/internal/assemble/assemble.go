// Package assemble renders REPORT.md from findings.json, coverage-ledger.json,
// stack.json and (optionally) inventory.json. It is deterministic: the same
// inputs always give the same bytes, and it never judges, re-ranks or
// re-words a finding. Every input is schema-validated first; invalid input is
// refused. Coverage statements come only from the ledger.
package assemble

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// Options names the input files. Findings and Ledger are required. Stack and
// Inventory are optional: an empty path means "not recorded". Repo is the
// audited source tree used to quote constraint lines verbatim; when empty the
// assembler uses stack.json's repo if that directory exists.
type Options struct {
	Findings  string
	Ledger    string
	Stack     string
	Inventory string
	Repo      string
}

// Result is a rendered report.
type Result struct {
	Report   string
	Warnings []string
	Summary  string
}

// InvalidError reports input that failed validation. The caller must not
// write a report.
type InvalidError struct {
	Problems []string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("invalid input (%d problems): %s", len(e.Problems), strings.Join(e.Problems, "; "))
}

// IsInvalid reports whether err is an *InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

// banned are claims the report must never make (SKILL.md hard rule 7). They
// are matched case-insensitively in every free-text field the report prints
// outside code blocks.
var banned = regexp.MustCompile(`(?i)\b(verified[ -]clean|fully[ -]audited|no (known )?vulnerabilit(y|ies)|no bugs|bug[ -]free|(is|are) (fully |now )?secure\b|guaranteed (secure|safe))`)

// Assemble validates the inputs and renders the report.
func Assemble(opt Options) (*Result, error) {
	var problems []string
	var warnings []string
	load := func(kind, p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", kind, err))
			return nil
		}
		rep, err := validate.Document(kind, b)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s %s: %v", kind, p, err))
			return nil
		}
		for _, e := range rep.Errors {
			problems = append(problems, fmt.Sprintf("%s %s: %s", kind, p, e))
		}
		for _, w := range rep.Warnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", kind, w))
		}
		if !rep.OK() {
			return nil
		}
		return b
	}
	if opt.Findings == "" || opt.Ledger == "" {
		return nil, fmt.Errorf("assemble: findings and ledger paths are required")
	}
	fb := load("findings", opt.Findings)
	lb := load("ledger", opt.Ledger)
	var sb []byte
	if opt.Stack != "" {
		sb = load("stack", opt.Stack)
	}
	if len(problems) > 0 {
		return nil, &InvalidError{Problems: problems}
	}
	in := &input{}
	if err := json.Unmarshal(fb, &in.f); err != nil {
		return nil, &InvalidError{Problems: []string{"findings: " + err.Error()}}
	}
	if err := json.Unmarshal(lb, &in.l); err != nil {
		return nil, &InvalidError{Problems: []string{"ledger: " + err.Error()}}
	}
	if sb != nil {
		in.s = &detect.Stack{}
		if err := json.Unmarshal(sb, in.s); err != nil {
			return nil, &InvalidError{Problems: []string{"stack: " + err.Error()}}
		}
	}
	if opt.Inventory != "" {
		b, err := os.ReadFile(opt.Inventory)
		if err != nil {
			return nil, fmt.Errorf("inventory: %w", err)
		}
		in.inv = &Inventory{}
		if err := json.Unmarshal(b, in.inv); err != nil {
			return nil, &InvalidError{Problems: []string{"inventory: " + err.Error()}}
		}
	}
	if p := checkClaims(&in.f); len(p) > 0 {
		return nil, &InvalidError{Problems: p}
	}
	in.repo = opt.Repo
	if in.repo == "" && in.s != nil {
		if st, err := os.Stat(in.s.Repo); err == nil && st.IsDir() {
			in.repo = in.s.Repo
		}
	}
	warnings = append(warnings, crossCheck(in)...)
	r := render(in)
	return &Result{Report: r, Warnings: warnings, Summary: in.summary()}, nil
}

type input struct {
	f    Findings
	l    Ledger
	s    *detect.Stack
	inv  *Inventory
	repo string
}

func checkClaims(f *Findings) []string {
	var out []string
	chk := func(where, s string) {
		if m := banned.FindString(s); m != "" {
			out = append(out, fmt.Sprintf("findings: %s contains the forbidden claim %q (SKILL.md hard rule 7: say what was examined instead)", where, m))
		}
	}
	chk("posture", f.Posture)
	chk("no_findings_reason", f.NoFindingsReason)
	for i, s := range f.OutOfScope {
		chk(fmt.Sprintf("out_of_scope[%d]", i), s)
	}
	for i, h := range f.Hardening {
		chk(fmt.Sprintf("hardening[%d]", i), h.Title+" "+h.Detail)
	}
	for i, r := range f.Records {
		chk(fmt.Sprintf("records[%d] (%s)", i, r.Fingerprint), strings.Join([]string{r.Title, r.Description, r.Impact, r.Unverified, r.ValidationPlan}, " "))
	}
	return out
}

// crossCheck returns warnings for inconsistencies between the documents.
func crossCheck(in *input) []string {
	var w []string
	if in.l.RunID != "" && in.l.RunID != in.f.RunID {
		w = append(w, fmt.Sprintf("ledger run_id %s differs from findings run_id %s", in.l.RunID, in.f.RunID))
	}
	fps := map[string]bool{}
	for _, r := range in.f.Records {
		fps[r.Fingerprint] = true
	}
	// Locations past the end of their file: agents misnumber lines.
	lines := map[string]int{}
	checkLoc := func(at string, l Location) {
		n, ok := lines[l.File]
		if !ok {
			if c, found := in.lineCount(l.File); found {
				n = c
			} else {
				n = -1
			}
			lines[l.File] = n
		}
		if n >= 0 && (l.Line > n || l.EndLine > n) {
			w = append(w, fmt.Sprintf("%s: location %s is past the end of %s (%d lines)", at, locStr(l), l.File, n))
		}
	}
	for _, r := range in.f.Records {
		at := "record " + r.Fingerprint
		checkLoc(at, r.Location)
		for _, l := range r.RelatedLocations {
			checkLoc(at+" related", l)
		}
		if r.RefutingLocation != nil {
			checkLoc(at+" refuting", *r.RefutingLocation)
		}
	}
	for _, u := range in.l.Units {
		for _, fp := range u.ResultFingerprints {
			if !fps[fp] {
				w = append(w, fmt.Sprintf("ledger unit %s lists fingerprint %q that is not in findings.json", u.ID, fp))
			}
		}
		if u.Status == "planned" || u.Status == "in_progress" {
			w = append(w, fmt.Sprintf("ledger unit %s is still %s; the report lists it as not examined", u.ID, u.Status))
		}
	}
	return w
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func conf(r *Record) int {
	if r.Confidence == nil {
		return -1
	}
	return *r.Confidence
}

// sortRanked sorts by severity, then confidence (high first), then title,
// then fingerprint so the order is total.
func sortRanked(rs []*Record) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if conf(a) != conf(b) {
			return conf(a) > conf(b)
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.Fingerprint < b.Fingerprint
	})
}

func (in *input) byVerdict(v string) []*Record {
	var out []*Record
	for i := range in.f.Records {
		if in.f.Records[i].Verdict == v {
			out = append(out, &in.f.Records[i])
		}
	}
	return out
}

func (in *input) summary() string {
	ex, app := in.examined()
	return fmt.Sprintf("%d confirmed · %d needs_validation · %d leads · %d rejected · ledger: %d of %d applicable units examined",
		len(in.byVerdict("confirmed")), len(in.byVerdict("needs_validation")), len(in.byVerdict("lead")), len(in.byVerdict("rejected")), ex, app)
}

// examined counts covered or candidate units, and units that apply (all
// minus not_applicable and out_of_scope).
func (in *input) examined() (int, int) {
	ex, app := 0, 0
	for _, u := range in.l.Units {
		switch u.Status {
		case "covered", "candidate":
			ex++
			app++
		case "not_applicable", "out_of_scope":
		default:
			app++
		}
	}
	return ex, app
}

func repoName(r string) string {
	r = strings.TrimRight(filepath.ToSlash(r), "/")
	if r == "" {
		return "?"
	}
	return path.Base(r)
}
