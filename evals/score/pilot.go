package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Human is a human auditor's findings for a pilot (evals/pilots/): the
// answer key of a real codebase, built after both reviews are done.
type Human struct {
	SchemaVersion string `json:"schema_version"`
	Pilot         string `json:"pilot"`
	Target        struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"target"`
	Auditor  string         `json:"auditor"`
	Report   string         `json:"report"`
	Findings []HumanFinding `json:"findings"`
}

// HumanFinding is one finding of the human report.
type HumanFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line"`
	// Match is an optional regular expression the matching zk-audit record
	// must contain (title, description, bug class or fingerprint).
	Match string `json:"match"`
	Class string `json:"class"`
	// Also lists further file:line or file:line-end places of the finding.
	Also []string `json:"also"`
}

var severities = []string{"critical", "high", "medium", "low", "info"}

var reLoc = regexp.MustCompile(`^([^:]+):([0-9]+)(?:-([0-9]+))?$`)

func parseLoc(s string) (string, int, int, error) {
	m := reLoc.FindStringSubmatch(strings.Trim(strings.TrimSpace(s), "`"))
	if m == nil {
		return "", 0, 0, fmt.Errorf("location %q is not file:line or file:line-end", s)
	}
	a, _ := strconv.Atoi(m[2])
	b := a
	if m[3] != "" {
		b, _ = strconv.Atoi(m[3])
	}
	return m[1], a, b, nil
}

// loadHuman reads the human findings as JSON, or as Markdown: a table with
// the columns Id, Title, Severity, Location (file:line or file:line-end)
// and optional Match and Class; "Pilot:", "Target:", "Commit:" and
// "Auditor:" lines fill the header.
func loadHuman(path string) (*Human, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h Human
	if strings.HasSuffix(path, ".json") {
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&h); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		var cols []string
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			for _, f := range []struct {
				key string
				dst *string
			}{{"Pilot:", &h.Pilot}, {"Target:", &h.Target.Name}, {"Commit:", &h.Target.Commit}, {"Auditor:", &h.Auditor}, {"Report:", &h.Report}} {
				if v, ok := strings.CutPrefix(line, f.key); ok {
					*f.dst = strings.Trim(strings.TrimSpace(v), "`")
				}
			}
			if !strings.HasPrefix(line, "|") {
				cols = nil
				continue
			}
			cells := splitCells(line)
			if cols == nil {
				cols = make([]string, len(cells))
				for i, c := range cells {
					cols[i] = strings.ToLower(c)
				}
				continue
			}
			if strings.HasPrefix(cells[0], "---") || strings.HasPrefix(cells[0], ":--") {
				continue
			}
			get := func(name string) string {
				for i, c := range cols {
					if c == name && i < len(cells) {
						return cells[i]
					}
				}
				return ""
			}
			f := HumanFinding{ID: get("id"), Title: get("title"), Severity: strings.ToLower(get("severity")), Match: strings.Trim(get("match"), "`"), Class: get("class")}
			locs := strings.Split(get("location"), ",")
			file, a, e, err := parseLoc(locs[0])
			if err != nil {
				return nil, fmt.Errorf("%s: finding %s: %w", path, f.ID, err)
			}
			f.File, f.Line, f.EndLine = file, a, e
			for _, l := range locs[1:] {
				f.Also = append(f.Also, strings.TrimSpace(l))
			}
			h.Findings = append(h.Findings, f)
		}
		h.SchemaVersion = "1"
	}
	if len(h.Findings) == 0 {
		return nil, fmt.Errorf("%s: no findings (a pilot needs the human's findings, even if all are low)", path)
	}
	seen := map[string]bool{}
	for _, f := range h.Findings {
		if f.ID == "" || seen[f.ID] {
			return nil, fmt.Errorf("%s: missing or duplicate finding id %q", path, f.ID)
		}
		seen[f.ID] = true
		if !contains(severities, f.Severity) {
			return nil, fmt.Errorf("%s: finding %s: severity %q (want %s)", path, f.ID, f.Severity, strings.Join(severities, ", "))
		}
		if f.File == "" || f.Line < 1 {
			return nil, fmt.Errorf("%s: finding %s needs file and line", path, f.ID)
		}
	}
	return &h, nil
}

// highOrCritical is the pass criterion's scope.
func highOrCritical(sev string) bool { return sev == "high" || sev == "critical" }

// pilotKey turns the human findings into an answer key: a zk-audit record
// matches a finding when it points within 3 lines of the finding's range
// (and its text matches Match, when given). Confirmed and needs_validation
// records find it; a lead is partial; anything else (no record, a rejected
// record, a hardening note) misses it.
func pilotKey(h *Human) (*Key, error) {
	k := &Key{SchemaVersion: "1", Case: "pilot " + h.Pilot, Fixture: h.Target.Name, Items: []*Item{}, Decoys: []*Item{}, Other: []*Item{}}
	for _, f := range h.Findings {
		end := f.EndLine
		if end < f.Line {
			end = f.Line
		}
		it := &Item{ID: f.ID, Title: f.Title, Class: f.Class, Match: f.Match, Critical: highOrCritical(f.Severity),
			Ranges:   []Range{{File: f.File, Lines: []int{f.Line, end}}},
			Expect:   []string{"confirmed", "needs_validation"},
			Partial:  []string{"lead"},
			Severity: []string{f.Severity}}
		for _, a := range f.Also {
			file, x, y, err := parseLoc(a)
			if err != nil {
				return nil, fmt.Errorf("finding %s: %w", f.ID, err)
			}
			it.Ranges = append(it.Ranges, Range{File: file, Lines: []int{x, y}})
		}
		if it.Match != "" {
			re, err := regexp.Compile(it.Match)
			if err != nil {
				return nil, fmt.Errorf("finding %s: match: %w", f.ID, err)
			}
			it.re = re
		}
		k.Items = append(k.Items, it)
	}
	return k, nil
}

// PilotResult is one scored pilot.
type PilotResult struct {
	Pilot        string   `json:"pilot"`
	Target       string   `json:"target"`
	Commit       string   `json:"commit"`
	Auditor      string   `json:"auditor"`
	Human        int      `json:"human_findings"`
	HighCritical int      `json:"human_high_or_critical"`
	Found        []string `json:"found"`     // confirmed or needs_validation at the place
	LeadOnly     []string `json:"lead_only"` // only a lead: not a miss, reported
	Misses       []string `json:"high_critical_misses"`
	OtherMissed  []string `json:"other_missed"` // medium and below, for the record
	// Unmatched are zk-audit claims (confirmed, needs_validation) at no
	// human finding: the human classifies each as a bug they missed or a
	// false positive.
	Unmatched []string `json:"unmatched_claims"`
	Pass      bool     `json:"pass"`
	Score     *Result  `json:"score"`
	Row       string   `json:"results_row"`
	Note      string   `json:"note"`
}

func scorePilot(h *Human, k *Key, es []entry) *PilotResult {
	res := score(k, es)
	sev := map[string]string{}
	for _, f := range h.Findings {
		sev[f.ID] = f.Severity
	}
	p := &PilotResult{Pilot: h.Pilot, Target: h.Target.Name, Commit: h.Target.Commit, Auditor: h.Auditor, Human: len(h.Findings), Score: res,
		Found: []string{}, LeadOnly: []string{}, Misses: []string{}, OtherMissed: []string{},
		Note: "automatic outcomes; the human auditor checks each one by hand before the result is recorded (docs/pilots.md)"}
	for _, it := range res.Items {
		hc := highOrCritical(sev[it.ID])
		if hc {
			p.HighCritical++
		}
		label := it.ID + " (" + sev[it.ID] + ")"
		switch {
		case it.Outcome == "found":
			p.Found = append(p.Found, label)
		case it.Outcome == "partial":
			p.LeadOnly = append(p.LeadOnly, label)
		case hc:
			p.Misses = append(p.Misses, label)
		default:
			p.OtherMissed = append(p.OtherMissed, label)
		}
	}
	p.Unmatched = append([]string{}, res.FalsePositives...)
	sort.Strings(p.Misses)
	p.Pass = len(p.Misses) == 0
	verdict := "pass"
	if !p.Pass {
		verdict = "FAIL: " + strings.Join(p.Misses, ", ")
	}
	p.Row = fmt.Sprintf("| %s | %s | `%s` | %d | %d | %d | %d | %d | %s |", h.Pilot, h.Target.Name, short(h.Target.Commit), len(h.Findings), p.HighCritical,
		len(p.Found), len(p.LeadOnly), len(p.Misses), verdict)
	return p
}

func short(c string) string {
	if len(c) > 10 {
		return c[:10]
	}
	return c
}

// cmdPilot scores a zk-audit run against a human auditor's findings.
func cmdPilot(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pilot", flag.ContinueOnError)
	humanPath := fs.String("human", "", "the human auditor's findings (.json or .md; templates in evals/pilots/)")
	target := fs.String("target", "", "the audited tree at the pilot commit (unmodified)")
	findings := fs.String("findings", "", "the zk-audit run's findings.json")
	keyOut := fs.String("key-out", "", "also write the answer key built from the human findings")
	out := fs.String("json", "", "also write the result here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *humanPath == "" || *target == "" || *findings == "" {
		return fmt.Errorf("pilot: --human, --target and --findings are required")
	}
	h, err := loadHuman(*humanPath)
	if err != nil {
		return err
	}
	k, err := pilotKey(h)
	if err != nil {
		return err
	}
	if err := k.resolve(*target); err != nil {
		return err
	}
	if *keyOut != "" {
		b, _ := json.MarshalIndent(k, "", "  ")
		if err := os.WriteFile(*keyOut, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	es, err := loadFindings(*findings)
	if err != nil {
		return err
	}
	p := scorePilot(h, k, es)
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
	}
	_, err = stdout.Write(b)
	return err
}

// splitCells splits a Markdown table row; `\|` is a literal bar.
func splitCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	if strings.HasSuffix(line, "|") && !strings.HasSuffix(line, "\\|") {
		line = line[:len(line)-1]
	}
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteByte('|')
			i++
		case line[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}
