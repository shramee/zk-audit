// Package companion converts the output of companion skills into
// zk-audit findings records.
//
// pashov solidity-auditor writes, for every scan, a runs directory
// `.solidity-auditor/runs/<stamp>/` with one `run-K.md` per pass and the
// assembled `full-report.md` (pashov/skills solidity-auditor,
// references/dedup-and-assembly.md Turn 4 step 5a and
// references/report-formatting.md). A run file bounds every finding and
// lead with `<!--F key=contract|function|bug-class conf=N kind=FINDING|LEAD
// agents=N-->` ... `<!--/F-->`; the full report carries the same blocks
// without the markers. ConvertPashov reads either and maps each item to a
// zk-audit `lead` record with `detected_by: solidity-auditor`: the run
// files carry no exploit proof, so under zk-audit's rules (a FINDING needs a
// proof) every converted item enters judging as a lead, and the judge
// promotes it after re-deriving the call sequence from source.
package companion

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

// Pashov is the companion name records carry in detected_by.
const Pashov = "solidity-auditor"

// Location is a findings.json location.
type Location struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Scope string `json:"scope"`
}

// Record is a findings.json lead record.
type Record struct {
	Fingerprint string   `json:"fingerprint"`
	Verdict     string   `json:"verdict"`
	Title       string   `json:"title"`
	Layer       string   `json:"layer"`
	BugClass    string   `json:"bug_class"`
	Location    Location `json:"location"`
	DetectedBy  []string `json:"detected_by"`
	Description string   `json:"description"`
	CodeSmells  []string `json:"code_smells"`
	Unverified  string   `json:"unverified"`
}

// Item is what the companion said about one record, kept beside it for the
// judge: its kind and confidence, in how many runs it appeared, and its
// proposed fix.
type Item struct {
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
	Kind        string `json:"kind"`
	Confidence  int    `json:"confidence,omitempty"`
	Seen        string `json:"seen,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

// Unresolved is an item whose contract the inventory does not know; it is
// reported, never dropped silently.
type Unresolved struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// Result is the document `gnark-inventory convert pashov` writes.
type Result struct {
	SchemaVersion string       `json:"schema_version"`
	Companion     string       `json:"companion"`
	Input         string       `json:"input"`
	Format        string       `json:"format"`
	Runs          int          `json:"runs"`
	Records       []Record     `json:"records"`
	Items         []Item       `json:"items"`
	Unresolved    []Unresolved `json:"unresolved"`
	Warnings      []string     `json:"warnings,omitempty"`
}

// block is one parsed finding or lead.
type block struct {
	key, kind, title, loc, desc, smells, fix string
	conf, pass                               int
	seen                                     int
}

var (
	reRun      = regexp.MustCompile(`^<!--RUN\s+(.*?)\s*-->\s*$`)
	reOpen     = regexp.MustCompile(`^<!--F\s+(.*?)\s*-->\s*$`)
	reClose    = regexp.MustCompile(`^<!--/F-->\s*$`)
	reTitle    = regexp.MustCompile(`^\[(\d+)\]\s+\*\*(?:\d+\.\s+)?(.+?)\*\*\s*$`)
	reLocLine  = regexp.MustCompile("^`([^`]+)`\\s*·")
	reLeadLine = regexp.MustCompile("^- \\*\\*(.+?)\\*\\* — (?:`([^`]*)`)?(.*)$")
	reSlug     = regexp.MustCompile(`[^a-z0-9]+`)
)

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Fields(s) {
		if i := strings.IndexByte(f, '='); i > 0 {
			m[f[:i]] = f[i+1:]
		}
	}
	return m
}

// parseRun reads the marked blocks of one run file.
func parseRun(src string) ([]block, int, []string) {
	var out []block
	var warn []string
	pass := 0
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		if m := reRun.FindStringSubmatch(lines[i]); m != nil {
			pass, _ = strconv.Atoi(attrs(m[1])["pass"])
			continue
		}
		m := reOpen.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		a := attrs(m[1])
		j := i + 1
		for j < len(lines) && !reClose.MatchString(lines[j]) && !reOpen.MatchString(lines[j]) {
			j++
		}
		if j >= len(lines) || !reClose.MatchString(lines[j]) {
			warn = append(warn, fmt.Sprintf("block %q at line %d has no closing <!--/F--> marker; read up to the next block", a["key"], i+1))
		}
		b := parseBody(lines[i+1 : j])
		b.key, b.kind = a["key"], strings.ToUpper(a["kind"])
		if c, err := strconv.Atoi(a["conf"]); err == nil {
			b.conf = c
		}
		b.pass = pass
		if b.kind != "FINDING" && b.kind != "LEAD" {
			warn = append(warn, fmt.Sprintf("block %q at line %d: unknown kind %q, read as LEAD", a["key"], i+1, a["kind"]))
			b.kind = "LEAD"
		}
		out = append(out, b)
		if j < len(lines) && reOpen.MatchString(lines[j]) {
			j-- // the next block opens here; read it on the next turn
		}
		i = j
	}
	return out, pass, warn
}

// parseBody reads a finding block (title, location line, Description, Fix)
// or a one-line lead.
func parseBody(lines []string) block {
	var b block
	var desc []string
	inDesc, inFix := false, false
	var fix []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case inFix:
			if strings.HasPrefix(t, "```") {
				inFix = false
				continue
			}
			fix = append(fix, l)
		case b.title == "" && reTitle.MatchString(t):
			m := reTitle.FindStringSubmatch(t)
			b.conf, _ = strconv.Atoi(m[1])
			b.title = m[2]
		case b.title == "" && reLeadLine.MatchString(t):
			m := reLeadLine.FindStringSubmatch(t)
			b.title, b.loc = m[1], m[2]
			rest := m[3]
			// " · NEW — Code smells: a, b — description" or " — description"
			if i := strings.Index(rest, " — "); i >= 0 {
				rest = rest[i+len(" — "):]
			} else {
				rest = ""
			}
			if strings.HasPrefix(rest, "Code smells:") {
				rest = strings.TrimSpace(strings.TrimPrefix(rest, "Code smells:"))
				if i := strings.Index(rest, " — "); i >= 0 {
					b.smells, rest = rest[:i], rest[i+len(" — "):]
				} else {
					b.smells, rest = rest, ""
				}
			}
			b.desc = strings.TrimSpace(rest)
		case b.loc == "" && reLocLine.MatchString(t):
			b.loc = reLocLine.FindStringSubmatch(t)[1]
		case t == "**Description**":
			inDesc = true
		case t == "**Fix**" || strings.HasPrefix(t, "**Fix (Option"):
			inDesc = false
			if strings.HasPrefix(t, "**Fix (Option") && len(fix) > 0 {
				fix = append(fix, "")
			}
		case strings.HasPrefix(t, "```"):
			inDesc, inFix = false, true
		case inDesc && t != "":
			desc = append(desc, t)
		}
	}
	if len(desc) > 0 {
		b.desc = strings.Join(desc, " ")
	}
	b.fix = strings.TrimRight(strings.Join(fix, "\n"), "\n")
	return b
}

// parseReport reads the assembled full-report.md: numbered findings
// separated by `---` and one-line leads under `## Leads`.
func parseReport(src string) []block {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	var out []block
	findings, leads := src, ""
	if i := strings.Index(src, "\n## Leads"); i >= 0 {
		findings, leads = src[:i], src[i:]
	}
	if i := strings.Index(findings, "\nFindings List"); i >= 0 {
		findings = findings[:i]
	}
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		b := parseBody(cur)
		cur = nil
		if b.title != "" {
			b.kind = "FINDING"
			out = append(out, b)
		}
	}
	inFence := false
	for _, l := range strings.Split(findings, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
		}
		if !inFence && strings.TrimSpace(l) == "---" {
			flush()
			continue
		}
		cur = append(cur, l)
	}
	flush()
	for _, l := range strings.Split(leads, "\n") {
		if reLeadLine.MatchString(strings.TrimSpace(l)) {
			b := parseBody([]string{l})
			b.kind = "LEAD"
			out = append(out, b)
		}
	}
	return out
}

// Options for ConvertPashov.
type Options struct {
	In        string               // a runs directory, a run-K.md, or full-report.md
	Inventory *inventory.Inventory // resolves Contract.function to file:line; may be nil
}

// ConvertPashov reads solidity-auditor output and returns lead records.
func ConvertPashov(opt Options) (*Result, error) {
	res := &Result{SchemaVersion: "1", Companion: Pashov, Input: opt.In, Records: []Record{}, Items: []Item{}, Unresolved: []Unresolved{}}
	st, err := os.Stat(opt.In)
	if err != nil {
		return nil, err
	}
	var blocks []block
	switch {
	case st.IsDir():
		runs, _ := filepath.Glob(filepath.Join(opt.In, "run-*.md"))
		sort.Slice(runs, func(i, j int) bool { return runNum(runs[i]) < runNum(runs[j]) })
		if len(runs) > 0 {
			res.Format = "run files"
			for _, f := range runs {
				b, err := os.ReadFile(f)
				if err != nil {
					return nil, err
				}
				bs, pass, warn := parseRun(string(b))
				if pass == 0 {
					pass = runNum(f)
					for i := range bs {
						bs[i].pass = pass
					}
				}
				for _, w := range warn {
					res.Warnings = append(res.Warnings, filepath.Base(f)+": "+w)
				}
				blocks = append(blocks, bs...)
				res.Runs++
			}
			break
		}
		rep := filepath.Join(opt.In, "full-report.md")
		b, err := os.ReadFile(rep)
		if err != nil {
			return nil, fmt.Errorf("convert pashov: %s has no run-K.md and no full-report.md", opt.In)
		}
		res.Format, res.Runs = "full report", 1
		blocks = parseReport(string(b))
	default:
		b, err := os.ReadFile(opt.In)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(b), "<!--F ") {
			bs, _, warn := parseRun(string(b))
			for _, w := range warn {
				res.Warnings = append(res.Warnings, w)
			}
			res.Format, res.Runs, blocks = "run file", 1, bs
		} else {
			res.Format, res.Runs, blocks = "full report", 1, parseReport(string(b))
		}
	}
	for _, b := range merge(blocks) {
		convert(res, b, opt.Inventory)
	}
	return res, nil
}

func runNum(path string) int {
	n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "run-"), ".md"))
	return n
}

// merge keeps one block per key, the way the companion's own assembler
// does: the stronger kind, then the higher confidence, then the later pass;
// seen counts the passes that raised the key.
func merge(bs []block) []block {
	byKey := map[string]int{}
	passes := map[string]map[int]bool{}
	var out []block
	for _, b := range bs {
		k := b.key
		if k == "" {
			k = strings.ToLower(b.loc) + "|" + slug(b.title)
		}
		if passes[k] == nil {
			passes[k] = map[int]bool{}
		}
		passes[k][b.pass] = true
		i, ok := byKey[k]
		if !ok {
			byKey[k] = len(out)
			out = append(out, b)
			continue
		}
		o := out[i]
		better := rank(b.kind) > rank(o.kind) ||
			rank(b.kind) == rank(o.kind) && (b.conf > o.conf || b.conf == o.conf && b.pass >= o.pass)
		if better {
			out[i] = b
		}
	}
	for k, i := range byKey {
		out[i].seen = len(passes[k])
	}
	return out
}

func rank(kind string) int {
	if kind == "FINDING" {
		return 2
	}
	return 1
}

func slug(s string) string {
	s = strings.Trim(reSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	if s == "" {
		s = "solidity-auditor"
	}
	return s
}

func convert(res *Result, b block, inv *inventory.Inventory) {
	contract, fn := b.loc, ""
	if i := strings.LastIndexByte(b.loc, '.'); i > 0 {
		contract, fn = b.loc[:i], b.loc[i+1:]
	}
	keyParts := strings.Split(b.key, "|")
	class := ""
	if len(keyParts) == 3 {
		class = slug(keyParts[2])
		if contract == "" {
			contract, fn = keyParts[0], keyParts[1]
		}
	}
	if class == "" {
		class = slug(b.title)
	}
	loc, name, fnName, ok := resolve(inv, contract, fn)
	if !ok {
		res.Unresolved = append(res.Unresolved, Unresolved{Key: b.key, Kind: b.kind, Title: b.title, Location: b.loc,
			Reason: "contract " + contract + " is not in the inventory (out of scope, or the companion scanned other files)"})
		return
	}
	if fnName == "" {
		fnName = "-"
	}
	fp := name + "|" + fnName + "|" + class
	seen := ""
	if res.Runs > 1 && b.seen > 0 {
		seen = fmt.Sprintf("%d/%d", b.seen, res.Runs)
	}
	r := Record{Fingerprint: fp, Verdict: "lead", Title: nonEmpty(b.title, class), Layer: "integration", BugClass: class,
		Location: loc, DetectedBy: []string{Pashov}}
	r.Description = nonEmpty(b.desc, r.Title)
	if b.kind == "FINDING" {
		s := fmt.Sprintf("%s FINDING at confidence %d", Pashov, b.conf)
		if seen != "" {
			s += ", seen in " + seen + " runs"
		}
		r.CodeSmells = []string{s}
		r.Unverified = "the companion's run file carries no exploit proof: re-derive the call sequence from source and run the four gates before promoting it"
	} else {
		for _, x := range strings.Split(b.smells, ",") {
			if x = strings.TrimSpace(x); x != "" {
				r.CodeSmells = append(r.CodeSmells, x)
			}
		}
		if len(r.CodeSmells) == 0 {
			r.CodeSmells = []string{Pashov + " LEAD"}
		}
		r.Unverified = nonEmpty(afterNotVerified(b.desc), "the exploit path the companion could not complete")
		r.Description = nonEmpty(beforeNotVerified(b.desc), r.Title)
	}
	res.Records = append(res.Records, r)
	res.Items = append(res.Items, Item{Fingerprint: fp, Key: b.key, Kind: b.kind, Confidence: b.conf, Seen: seen, Fix: b.fix})
}

var notVerified = []string{"Not verified:", "Unverified:", "not verified:"}

func beforeNotVerified(s string) string {
	for _, p := range notVerified {
		if i := strings.Index(s, p); i >= 0 {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func afterNotVerified(s string) string {
	for _, p := range notVerified {
		if i := strings.Index(s, p); i >= 0 {
			return strings.TrimSpace(s[i+len(p):])
		}
	}
	return ""
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return strings.TrimSpace(s)
}

// resolve maps a contract and function name (any case: run-file keys are
// lower-cased) to the scanned contract and function, as spelled in source.
// A function the contract does not declare resolves to the contract's line.
func resolve(inv *inventory.Inventory, contract, fn string) (Location, string, string, bool) {
	if inv == nil || inv.Contracts == nil || contract == "" {
		return Location{}, "", "", false
	}
	var c *solidity.Contract
	for i := range inv.Contracts.Contracts {
		x := &inv.Contracts.Contracts[i]
		if strings.EqualFold(x.Name, contract) && (c == nil || c.Peripheral && !x.Peripheral) {
			c = x
		}
	}
	if c == nil {
		return Location{}, "", "", false
	}
	loc := Location{File: c.File, Line: max(c.Line, 1), Scope: c.Name}
	name := fn
	for _, f := range c.Functions {
		if strings.EqualFold(f.Name, fn) {
			name = f.Name
			loc.Line, loc.Scope = max(f.Line, 1), c.Name+"."+f.Name
			break
		}
	}
	return loc, c.Name, name, true
}
