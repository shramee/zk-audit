// Package threatmodel parses zk-audit.md, the threat-model file a
// repository keeps at its root, into threat-model.json. The file is
// Markdown that people write: level-2 headings name the sections and
// tables (or, for the scope, a bullet list) hold the entries, so the parser
// can give every entry its line for `trust.source` (zk-audit.md:12). The
// template is {skill}/templates/zk-audit.md.
//
// The threat model states intent. It never excuses a missing constraint:
// judging turns a trusted party's power into an accepted risk, never into a
// dropped item, and the report lists it.
package threatmodel

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// FileName is the threat-model file at the repository root.
const FileName = "zk-audit.md"

// OutName is the parsed file in the output directory.
const OutName = "threat-model.json"

// Trust levels of a party.
var TrustLevels = []string{"trusted", "bounded", "untrusted"}

// Statuses of a prior finding.
var PriorStatuses = []string{"open", "fixed", "acknowledged", "wont-fix", "duplicate"}

// ScopePath is one in-scope path.
type ScopePath struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

// OutPath is one out-of-scope path or area.
type OutPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Line   int    `json:"line"`
}

// Party is one trusted party.
type Party struct {
	Party  string `json:"party"`
	Trust  string `json:"trust"`
	Powers string `json:"powers"`
	Notes  string `json:"notes"`
	Line   int    `json:"line"`
}

// Property is one property that must hold.
type Property struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Line int    `json:"line"`
}

// Risk is one accepted risk.
type Risk struct {
	ID    string `json:"id"`
	Party string `json:"party"`
	Risk  string `json:"risk"`
	Notes string `json:"notes"`
	Line  int    `json:"line"`
}

// Prior is one finding of an earlier review.
type Prior struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	Title       string `json:"title"`
	Line        int    `json:"line"`
}

// Fact is one deployment fact.
type Fact struct {
	Fact  string `json:"fact"`
	Value string `json:"value"`
	Line  int    `json:"line"`
}

// Scope holds the in-scope and out-of-scope paths.
type Scope struct {
	In  []ScopePath `json:"in"`
	Out []OutPath   `json:"out"`
}

// Doc is threat-model.json.
type Doc struct {
	SchemaVersion  string     `json:"schema_version"`
	Source         string     `json:"source"`
	SHA256         string     `json:"sha256"`
	Scope          Scope      `json:"scope"`
	TrustedParties []Party    `json:"trusted_parties"`
	Properties     []Property `json:"properties"`
	AcceptedRisks  []Risk     `json:"accepted_risks"`
	PriorFindings  []Prior    `json:"prior_findings"`
	Deployment     []Fact     `json:"deployment"`
	Warnings       []string   `json:"warnings"`
}

// Error lists every problem of an invalid file.
type Error struct{ Problems []string }

func (e *Error) Error() string { return strings.Join(e.Problems, "; ") }

// sections maps a normalised heading to its key.
var sections = map[string]string{
	"scope": "scope", "in scope": "scope",
	"out of scope":    "out",
	"trusted parties": "parties", "trust": "parties", "trusted party": "parties",
	"properties": "properties", "properties that must hold": "properties", "invariants": "properties",
	"accepted risks": "risks", "accepted risk": "risks",
	"prior findings": "prior", "known issues": "prior", "previous findings": "prior",
	"deployment": "deployment", "deployment facts": "deployment",
}

var (
	reID          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[0-9]+$`)
	reFingerprint = regexp.MustCompile(`^[^|]+\|[^|]+\|[a-z0-9][a-z0-9-]*$`)
	rePlaceholder = regexp.MustCompile(`^<[^>]*>$`)
)

type table struct {
	header     []string
	headerLine int
	sep        bool
	rows       [][]string
	lines      []int
}

func splitRow(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '|':
			cur.WriteByte('|')
			i++
		case s[i] == '|':
			cells = append(cells, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	cells = append(cells, cur.String())
	for i, c := range cells {
		c = strings.TrimSpace(c)
		if len(c) >= 2 && strings.HasPrefix(c, "`") && strings.HasSuffix(c, "`") && !strings.Contains(c[1:len(c)-1], "`") {
			c = c[1 : len(c)-1]
		}
		cells[i] = c
	}
	return cells
}

var reSep = regexp.MustCompile(`^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$`)

// Parse reads the file's bytes. repo, when set, is used to warn about
// in-scope paths that do not exist.
func Parse(b []byte, repo string) (*Doc, error) {
	d := &Doc{SchemaVersion: "1", Source: FileName, SHA256: fmt.Sprintf("%x", sha256.Sum256(b)),
		Scope: Scope{In: []ScopePath{}, Out: []OutPath{}}, TrustedParties: []Party{}, Properties: []Property{},
		AcceptedRisks: []Risk{}, PriorFindings: []Prior{}, Deployment: []Fact{}, Warnings: []string{}}
	var problems []string
	bad := func(line int, f string, a ...any) {
		problems = append(problems, fmt.Sprintf("%s:%d: %s", FileName, line, fmt.Sprintf(f, a...)))
	}
	warn := func(line int, f string, a ...any) {
		d.Warnings = append(d.Warnings, fmt.Sprintf("%s:%d: %s", FileName, line, fmt.Sprintf(f, a...)))
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	section := ""
	seen := map[string]bool{}
	inFence, inComment := false, false
	var tbl *table
	tables := map[string][]*table{}
	bullets := map[string][]ScopePath{}
	flush := func() {
		if tbl != nil && section != "" {
			tables[section] = append(tables[section], tbl)
		}
		tbl = nil
	}
	for i, raw := range lines {
		n := i + 1
		line := strings.TrimSpace(raw)
		if inComment {
			if strings.Contains(line, "-->") {
				inComment = false
			}
			continue
		}
		if strings.HasPrefix(line, "<!--") {
			if !strings.Contains(line, "-->") {
				inComment = true
			}
			continue
		}
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			flush()
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(line, "## ") {
			flush()
			h := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "## ")))
			h = strings.TrimRight(h, ":")
			key, ok := sections[h]
			if !ok {
				warn(n, "section %q is not one the parser reads (scope, out of scope, trusted parties, properties, accepted risks, prior findings, deployment); it is ignored", strings.TrimPrefix(line, "## "))
				section = ""
				continue
			}
			if seen[key] {
				bad(n, "section %q appears twice", h)
			}
			seen[key] = true
			section = key
			continue
		}
		if strings.HasPrefix(line, "# ") {
			flush()
			section = ""
			continue
		}
		if section == "" {
			continue
		}
		if strings.HasPrefix(line, "|") {
			if tbl == nil {
				tbl = &table{header: lowerAll(splitRow(line)), headerLine: n}
				continue
			}
			if !tbl.sep && len(tbl.rows) == 0 {
				if !reSep.MatchString(line) {
					bad(n, "a table header must be followed by a |---| separator row")
				}
				tbl.sep = true
				continue
			}
			tbl.rows = append(tbl.rows, splitRow(line))
			tbl.lines = append(tbl.lines, n)
			continue
		}
		flush()
		if section == "scope" && (strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ")) {
			p := strings.Trim(strings.TrimSpace(line[2:]), "`")
			if p != "" && !rePlaceholder.MatchString(p) {
				bullets["scope"] = append(bullets["scope"], ScopePath{Path: p, Line: n})
			}
		}
	}
	flush()

	// rows of a section's tables, with column lookup by header prefix
	type row struct {
		get  func(col string) string
		line int
	}
	rowsOf := func(sec string, required ...string) []row {
		var out []row
		for _, t := range tables[sec] {
			idx := map[string]int{}
			for i, h := range t.header {
				f := strings.Fields(h)
				if len(f) > 0 {
					if _, dup := idx[f[0]]; !dup {
						idx[f[0]] = i
					}
				}
			}
			ok := true
			for _, c := range required {
				if _, has := idx[c]; !has {
					bad(t.headerLine, "the %s table needs a %q column (has %s)", sec, c, strings.Join(t.header, ", "))
					ok = false
				}
			}
			if !ok {
				continue
			}
			for k, cells := range t.rows {
				ln := t.lines[k]
				get := func(col string) string {
					if i, has := idx[col]; has && i < len(cells) {
						return cells[i]
					}
					return ""
				}
				placeholder, empty := false, true
				for _, c := range cells {
					if c != "" {
						empty = false
					}
					if rePlaceholder.MatchString(c) {
						placeholder = true
					}
				}
				if empty {
					continue
				}
				if placeholder {
					warn(ln, "row still holds a template placeholder (<...>); it is ignored")
					continue
				}
				out = append(out, row{get: get, line: ln})
			}
		}
		return out
	}

	for _, p := range bullets["scope"] {
		if checkPath(p.Path) != "" {
			bad(p.Line, "scope path %q: %s", p.Path, checkPath(p.Path))
			continue
		}
		if repo != "" {
			if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p.Path))); err != nil {
				warn(p.Line, "scope path %q does not exist in the repository", p.Path)
			}
		}
		d.Scope.In = append(d.Scope.In, p)
	}
	for _, r := range rowsOf("scope", "path") {
		p := ScopePath{Path: r.get("path"), Line: r.line}
		if msg := checkPath(p.Path); msg != "" {
			bad(r.line, "scope path %q: %s", p.Path, msg)
			continue
		}
		d.Scope.In = append(d.Scope.In, p)
	}
	for _, r := range rowsOf("out", "path") {
		p := OutPath{Path: r.get("path"), Reason: r.get("reason"), Line: r.line}
		if p.Path == "" {
			bad(r.line, "out-of-scope row without a path")
			continue
		}
		if p.Reason == "" {
			warn(r.line, "out-of-scope %q has no reason", p.Path)
		}
		d.Scope.Out = append(d.Scope.Out, p)
	}
	parties := map[string]string{}
	for _, r := range rowsOf("parties", "party", "trust") {
		p := Party{Party: r.get("party"), Trust: strings.ToLower(r.get("trust")), Powers: r.get("powers"), Notes: r.get("notes"), Line: r.line}
		if p.Party == "" {
			bad(r.line, "trusted-party row without a party")
			continue
		}
		if !in(TrustLevels, p.Trust) {
			bad(r.line, "trust %q for %s (want %s)", p.Trust, p.Party, strings.Join(TrustLevels, ", "))
			continue
		}
		if p.Trust == "bounded" && p.Notes == "" {
			warn(r.line, "%s is bounded but Notes states no bound", p.Party)
		}
		if _, dup := parties[strings.ToLower(p.Party)]; dup {
			bad(r.line, "party %s is listed twice", p.Party)
		}
		parties[strings.ToLower(p.Party)] = p.Trust
		d.TrustedParties = append(d.TrustedParties, p)
	}
	ids := map[string]int{}
	checkID := func(id string, line int) bool {
		if !reID.MatchString(id) {
			bad(line, "id %q is not like AR-1, PROP-2 or PF-3", id)
			return false
		}
		if l, dup := ids[id]; dup {
			bad(line, "id %s is also used on line %d", id, l)
			return false
		}
		ids[id] = line
		return true
	}
	for _, r := range rowsOf("properties", "id", "property") {
		p := Property{ID: r.get("id"), Text: r.get("property"), Line: r.line}
		if !checkID(p.ID, r.line) {
			continue
		}
		if p.Text == "" {
			bad(r.line, "property %s is empty", p.ID)
			continue
		}
		d.Properties = append(d.Properties, p)
	}
	for _, r := range rowsOf("risks", "id", "party", "risk") {
		k := Risk{ID: r.get("id"), Party: r.get("party"), Risk: r.get("risk"), Notes: r.get("notes"), Line: r.line}
		if !checkID(k.ID, r.line) {
			continue
		}
		if k.Party == "" || k.Risk == "" {
			bad(r.line, "accepted risk %s needs a party and a risk", k.ID)
			continue
		}
		if t, ok := parties[strings.ToLower(k.Party)]; !ok {
			warn(r.line, "accepted risk %s names party %q, which the trusted-parties table does not list", k.ID, k.Party)
		} else if t == "untrusted" {
			bad(r.line, "accepted risk %s is accepted from %s, which the trusted-parties table marks untrusted", k.ID, k.Party)
			continue
		}
		d.AcceptedRisks = append(d.AcceptedRisks, k)
	}
	for _, r := range rowsOf("prior", "id", "fingerprint", "status") {
		p := Prior{ID: r.get("id"), Fingerprint: r.get("fingerprint"), Status: strings.ToLower(r.get("status")), Title: r.get("title"), Line: r.line}
		if !checkID(p.ID, r.line) {
			continue
		}
		if !reFingerprint.MatchString(p.Fingerprint) {
			bad(r.line, "prior finding %s: fingerprint %q is not <scope>|<subject>|<bug-class> (the group_key of a findings.json record)", p.ID, p.Fingerprint)
			continue
		}
		if !in(PriorStatuses, p.Status) {
			bad(r.line, "prior finding %s: status %q (want %s)", p.ID, p.Status, strings.Join(PriorStatuses, ", "))
			continue
		}
		d.PriorFindings = append(d.PriorFindings, p)
	}
	for _, r := range rowsOf("deployment", "fact", "value") {
		f := Fact{Fact: r.get("fact"), Value: r.get("value"), Line: r.line}
		if f.Fact == "" || f.Value == "" {
			warn(r.line, "deployment row without a fact or a value is ignored")
			continue
		}
		d.Deployment = append(d.Deployment, f)
	}
	if len(d.TrustedParties)+len(d.Properties)+len(d.AcceptedRisks)+len(d.PriorFindings)+len(d.Deployment)+len(d.Scope.In)+len(d.Scope.Out) == 0 {
		warn(1, "no entry was found; is it still the empty template?")
	}
	if len(problems) > 0 {
		return d, &Error{Problems: problems}
	}
	return d, nil
}

// Load reads <repo>/zk-audit.md (or file, when set). ok is false when the
// repository has no threat-model file.
func Load(repo, file string) (*Doc, bool, error) {
	if file == "" {
		file = filepath.Join(repo, FileName)
	}
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d, err := Parse(b, repo)
	return d, true, err
}

func checkPath(p string) string {
	switch {
	case p == "":
		return "empty"
	case strings.HasPrefix(p, "/") || filepath.IsAbs(p):
		return "must be relative to the repository root"
	case p == ".." || strings.HasPrefix(path.Clean(p), "../"):
		return "leaves the repository"
	}
	return ""
}

func lowerAll(xs []string) []string {
	for i, x := range xs {
		xs[i] = strings.ToLower(x)
	}
	return xs
}

func in(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// AcceptsLine reports whether line of zk-audit.md is an accepted risk or a
// party marked trusted (the lines `trust.source` may cite), and which.
func (d *Doc) AcceptsLine(line int) (string, bool) {
	for _, r := range d.AcceptedRisks {
		if r.Line == line {
			return "accepted risk " + r.ID, true
		}
	}
	for _, p := range d.TrustedParties {
		if p.Line == line && p.Trust == "trusted" {
			return "trusted party " + p.Party, true
		}
	}
	return "", false
}
