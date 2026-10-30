package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Findings is the part of findings.json the scorer reads.
type Findings struct {
	Records   []Record   `json:"records"`
	Hardening []Hardened `json:"hardening"`
}

type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
}

type Record struct {
	Fingerprint      string     `json:"fingerprint"`
	Verdict          string     `json:"verdict"`
	Title            string     `json:"title"`
	Layer            string     `json:"layer"`
	BugClass         string     `json:"bug_class"`
	Location         Location   `json:"location"`
	RelatedLocations []Location `json:"related_locations"`
	Description      string     `json:"description"`
	Severity         string     `json:"severity"`
	Evidence         string     `json:"evidence"`
	PoC              *struct {
		Path   string `json:"path"`
		Result string `json:"result"`
	} `json:"poc"`
}

type Hardened struct {
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Location *Location `json:"location"`
}

// rank orders verdict classes from strongest to weakest claim.
var rank = map[string]int{"confirmed": 4, "needs_validation": 3, "lead": 2, "hardening": 1, "rejected": 0}

// entry is a record or hardening note in a form the matcher can use.
type entry struct {
	class    string
	title    string
	head     string // title, bug class and fingerprint
	text     string // head plus description
	severity string
	locs     []Location
	poc      bool // evidence POC with a demonstrated result
	layer    string
}

func loadFindings(path string) ([]entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f Findings
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	var out []entry
	for _, r := range f.Records {
		e := entry{
			class:    r.Verdict,
			title:    r.Title,
			head:     strings.Join([]string{r.Title, r.BugClass, r.Fingerprint}, "\n"),
			text:     strings.Join([]string{r.Title, r.BugClass, r.Fingerprint, r.Description}, "\n"),
			severity: r.Severity,
			locs:     append([]Location{r.Location}, r.RelatedLocations...),
			layer:    r.Layer,
			poc:      r.Evidence == "POC" && r.PoC != nil && r.PoC.Result == "demonstrated",
		}
		out = append(out, e)
	}
	for _, h := range f.Hardening {
		e := entry{class: "hardening", title: h.Title, head: h.Title, text: h.Title + "\n" + h.Detail}
		if h.Location != nil {
			e.locs = []Location{*h.Location}
		}
		out = append(out, e)
	}
	return out, nil
}

// matches reports whether an entry points at the item and describes it.
func (it *Item) matches(e entry) bool {
	text := e.text
	if it.MatchIn == "title" {
		text = e.head
	}
	if it.re != nil && !it.re.MatchString(text) {
		return false
	}
	return it.touches(e.locs)
}

// primary reports whether the entry's own location, not a related one, is
// inside the item.
func (it *Item) primary(e entry) bool {
	return len(e.locs) > 0 && it.touches(e.locs[:1])
}

func (it *Item) touches(locs []Location) bool {
	for _, l := range locs {
		end := l.EndLine
		if end < l.Line {
			end = l.Line
		}
		for _, s := range it.resolved {
			if clean(l.File) != s.file {
				continue
			}
			if l.Line <= s.end+slack && end >= s.start-slack {
				return true
			}
		}
	}
	return false
}

func clean(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	return strings.TrimPrefix(p, "./")
}

// ItemResult is the outcome for one planted item or decoy.
type ItemResult struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Class      string   `json:"class,omitempty"`
	Outcome    string   `json:"outcome"` // found, partial, missed; decoys: handled, false_positive
	Best       string   `json:"best,omitempty"`
	SeverityOK *bool    `json:"severity_ok,omitempty"`
	Records    []string `json:"records,omitempty"`
}

// Result is the score of one run.
type Result struct {
	Case   string       `json:"case"`
	Label  string       `json:"label,omitempty"`
	Items  []ItemResult `json:"items"`
	Decoys []ItemResult `json:"decoys"`
	// Recall is nil for an all-safe fixture (no planted items): recall is
	// undefined, not zero, so summaries print it as "–".
	Recall         *float64 `json:"recall"`
	CriticalRecall *float64 `json:"critical_recall,omitempty"`
	Found          int      `json:"found"`
	Partial        int      `json:"partial"`
	Missed         int      `json:"missed"`
	FalsePositives []string `json:"false_positives"`
	Noise          []string `json:"noise"`
	Precision      *float64 `json:"precision,omitempty"`
	SeverityAgree  *float64 `json:"severity_agreement,omitempty"`
	PoCRate        *float64 `json:"poc_rate,omitempty"`
	CostUSD        *float64 `json:"cost_usd,omitempty"`
	DurationS      *float64 `json:"duration_s,omitempty"`
	Error          string   `json:"error,omitempty"`
}

func score(k *Key, es []entry) *Result {
	res := &Result{Case: k.Case, FalsePositives: []string{}, Noise: []string{}}
	used := make([]bool, len(es))
	critTotal, critFound := 0, 0.0
	sevTotal, sevOK := 0, 0
	for _, it := range k.Items {
		ir := ItemResult{ID: it.ID, Title: it.Title, Class: it.Class, Outcome: "missed"}
		// The strongest matching entry in an accepted class decides; a
		// matching entry in no accepted class is recorded but scores nothing.
		bestIdx, bestTier := -1, 0
		for i, e := range es {
			if !it.matches(e) {
				continue
			}
			used[i] = true
			ir.Records = append(ir.Records, e.class+": "+e.title)
			tier := 0
			switch {
			case contains(it.Expect, e.class):
				tier = 2
			case contains(it.Partial, e.class):
				tier = 1
			}
			// Within a tier the record that sits on the item itself wins over
			// one that only lists it as a related location (a dependency
			// record that cites the file); then the stronger verdict.
			better := bestIdx < 0 || tier > bestTier
			if !better && tier == bestTier {
				b := es[bestIdx]
				switch {
				case it.primary(e) != it.primary(b):
					better = it.primary(e)
				default:
					better = rank[e.class] > rank[b.class]
				}
			}
			if better {
				bestIdx, bestTier = i, tier
			}
		}
		if bestIdx >= 0 {
			b := es[bestIdx]
			ir.Best = b.class
			ir.Outcome = map[int]string{0: "missed", 1: "partial", 2: "found"}[bestTier]
			if len(it.Severity) > 0 && (b.class == "confirmed" || b.class == "needs_validation") {
				ok := contains(it.Severity, b.severity)
				ir.SeverityOK = &ok
				sevTotal++
				if ok {
					sevOK++
				}
			}
		}
		switch ir.Outcome {
		case "found":
			res.Found++
		case "partial":
			res.Partial++
		default:
			res.Missed++
		}
		if it.Critical {
			critTotal++
			critFound += map[string]float64{"found": 1, "partial": 0.5}[ir.Outcome]
		}
		res.Items = append(res.Items, ir)
	}
	for _, d := range k.Decoys {
		dr := ItemResult{ID: d.ID, Title: d.Title, Outcome: "handled"}
		for i, e := range es {
			if !d.matches(e) {
				continue
			}
			used[i] = true
			dr.Records = append(dr.Records, e.class+": "+e.title)
			if e.class == "confirmed" || e.class == "needs_validation" {
				dr.Outcome = "false_positive"
				dr.Best = e.class
			}
		}
		if dr.Outcome == "false_positive" {
			res.FalsePositives = append(res.FalsePositives, d.ID+" (decoy): "+strings.Join(dr.Records, "; "))
		}
		res.Decoys = append(res.Decoys, dr)
	}
	for i, e := range es {
		if used[i] {
			continue
		}
		other := false
		for _, o := range k.Other {
			if o.matches(e) {
				other = true
				break
			}
		}
		if other {
			continue
		}
		switch e.class {
		case "confirmed", "needs_validation":
			res.FalsePositives = append(res.FalsePositives, e.class+": "+e.title)
		case "lead", "hardening":
			res.Noise = append(res.Noise, e.class+": "+e.title)
		}
	}
	if n := len(k.Items); n > 0 {
		v := (float64(res.Found) + 0.5*float64(res.Partial)) / float64(n)
		res.Recall = &v
	}
	if critTotal > 0 {
		v := critFound / float64(critTotal)
		res.CriticalRecall = &v
	}
	// Precision over claims: confirmed and needs_validation entries that are
	// not false positives.
	claims, bad := 0, 0
	for _, e := range es {
		if e.class == "confirmed" || e.class == "needs_validation" {
			claims++
		}
	}
	bad = len(res.FalsePositives)
	if claims > 0 {
		v := float64(claims-bad) / float64(claims)
		if v < 0 {
			v = 0
		}
		res.Precision = &v
	}
	if sevTotal > 0 {
		v := float64(sevOK) / float64(sevTotal)
		res.SeverityAgree = &v
	}
	confirmedCircuit, withPoC := 0, 0
	for _, e := range es {
		if e.class == "confirmed" && e.layer == "circuit" {
			confirmedCircuit++
			if e.poc {
				withPoC++
			}
		}
	}
	if confirmedCircuit > 0 {
		v := float64(withPoC) / float64(confirmedCircuit)
		res.PoCRate = &v
	}
	sort.Strings(res.Noise)
	return res
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
