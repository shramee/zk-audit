// Package memory holds the loop-mode memory ledger (<out>/memory.json): every
// fingerprint seen across passes, with the passes it appeared in and its
// latest record. It decides NEW / KNOWN tags, "seen in k/N passes" and the
// stop rule, and writes the cumulative findings.json, so none of this is
// left to the orchestrator's prose.
package memory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// Item is one fingerprint in memory.
type Item struct {
	Fingerprint string          `json:"fingerprint"`
	Title       string          `json:"title"`
	Verdict     string          `json:"verdict"`
	Location    string          `json:"location"`
	FirstPass   int             `json:"first_pass"`
	Passes      []int           `json:"passes"`
	Record      json.RawMessage `json:"record"`
}

// Pass is the outcome of one merged pass.
type Pass struct {
	Pass         int      `json:"pass"`
	New          []string `json:"new"`
	Known        []string `json:"known"`
	MissingUnits int      `json:"missing_units"`
	CriticGiven  bool     `json:"critic_given"`
	Stop         bool     `json:"stop"`
	Reason       string   `json:"reason"`
}

// Memory is memory.json.
type Memory struct {
	SchemaVersion string `json:"schema_version"`
	PassesPlanned int    `json:"passes_planned"`
	Passes        []Pass `json:"passes"`
	Items         []Item `json:"items"`
}

// Path is the memory file of an output directory.
func Path(out string) string { return filepath.Join(out, "memory.json") }

// PassFindings is where pass p's judged records go.
func PassFindings(out string, p int) string {
	return filepath.Join(out, "passes", fmt.Sprint(p), "findings.json")
}

// Load reads memory.json; ok is false when it does not exist.
func Load(out string) (*Memory, bool, error) {
	b, err := os.ReadFile(Path(out))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var m Memory
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false, fmt.Errorf("memory.json: %w", err)
	}
	return &m, true, nil
}

func (m *Memory) save(out string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(out), append(b, '\n'), 0o644)
}

// Init creates memory.json for a run of n passes. Re-running it with the
// same n is a no-op; a different n after a pass was merged is an error.
func Init(out string, n int) (*Memory, error) {
	if n < 1 {
		return nil, fmt.Errorf("memory init: --passes must be at least 1")
	}
	m, ok, err := Load(out)
	if err != nil {
		return nil, err
	}
	if ok {
		if m.PassesPlanned == n || len(m.Passes) == 0 {
			m.PassesPlanned = n
			return m, m.save(out)
		}
		return nil, fmt.Errorf("memory init: memory.json already plans %d passes and has %d merged", m.PassesPlanned, len(m.Passes))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	m = &Memory{SchemaVersion: "1", PassesPlanned: n, Passes: []Pass{}, Items: []Item{}}
	return m, m.save(out)
}

type rec struct {
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Verdict     string `json:"verdict"`
	Location    struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"location"`
}

// Merge folds pass p's findings (a findings.json document) and the critic's
// missing-unit count into memory, writes memory.json and the cumulative
// <out>/findings.json, and returns the pass outcome. Re-merging the last
// pass replaces it. criticGiven=false means no critic ran this pass.
func Merge(out string, p int, findings []byte, missingUnits int, criticGiven bool) (*Pass, error) {
	m, ok, err := Load(out)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("memory merge: no memory.json; run `memory init --out %s --passes N` first", out)
	}
	last := len(m.Passes)
	switch {
	case p == last && last > 0:
		m.unmerge(p)
	case p != last+1:
		return nil, fmt.Errorf("memory merge: pass %d out of order (%d merged so far; next is %d)", p, last, last+1)
	case last > 0 && m.Passes[last-1].Stop:
		return nil, fmt.Errorf("memory merge: pass %d stopped the loop (%s); run no further pass", last, m.Passes[last-1].Reason)
	case p > m.PassesPlanned:
		return nil, fmt.Errorf("memory merge: pass %d is beyond the %d planned", p, m.PassesPlanned)
	}
	rep, err := validate.Document("findings", findings)
	if err != nil {
		return nil, err
	}
	if !rep.OK() {
		return nil, fmt.Errorf("memory merge: pass %d findings are invalid: %s", p, strings.Join(rep.Errors, "; "))
	}
	var doc struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(findings, &doc); err != nil {
		return nil, err
	}
	idx := map[string]int{}
	for i, it := range m.Items {
		idx[it.Fingerprint] = i
	}
	res := Pass{Pass: p, New: []string{}, Known: []string{}, MissingUnits: missingUnits, CriticGiven: criticGiven}
	for _, raw := range doc.Records {
		var r rec
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		clean := stripLoopFields(raw)
		loc := fmt.Sprintf("%s:%d", r.Location.File, r.Location.Line)
		if i, ok := idx[r.Fingerprint]; ok {
			it := &m.Items[i]
			it.Passes = appendPass(it.Passes, p)
			it.Title, it.Verdict, it.Location, it.Record = r.Title, r.Verdict, loc, clean
			res.Known = append(res.Known, r.Fingerprint)
			continue
		}
		idx[r.Fingerprint] = len(m.Items)
		m.Items = append(m.Items, Item{Fingerprint: r.Fingerprint, Title: r.Title, Verdict: r.Verdict, Location: loc,
			FirstPass: p, Passes: []int{p}, Record: clean})
		res.New = append(res.New, r.Fingerprint)
	}
	sort.Strings(res.New)
	sort.Strings(res.Known)
	switch {
	case p >= m.PassesPlanned:
		res.Stop, res.Reason = true, fmt.Sprintf("all %d planned passes ran", m.PassesPlanned)
	case len(res.New) == 0 && missingUnits == 0:
		res.Stop, res.Reason = true, fmt.Sprintf("pass %d added no new fingerprint and the critic reported no missing unit", p)
		if !criticGiven {
			res.Reason = fmt.Sprintf("pass %d added no new fingerprint (no critic output given)", p)
		}
	case len(res.New) == 0:
		res.Reason = fmt.Sprintf("no new fingerprint, but the critic reported %d missing units: run pass %d", missingUnits, p+1)
	default:
		res.Reason = fmt.Sprintf("%d new fingerprints: run pass %d", len(res.New), p+1)
	}
	m.Passes = append(m.Passes, res)
	sort.Slice(m.Items, func(i, j int) bool { return m.Items[i].Fingerprint < m.Items[j].Fingerprint })
	cum, err := m.cumulative(findings)
	if err != nil {
		return nil, err
	}
	if err := m.save(out); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, "findings.json"), cum, 0o644); err != nil {
		return nil, err
	}
	return &res, nil
}

// unmerge removes pass p (the last one) so it can be merged again.
func (m *Memory) unmerge(p int) {
	m.Passes = m.Passes[:len(m.Passes)-1]
	var keep []Item
	for _, it := range m.Items {
		var ps []int
		for _, x := range it.Passes {
			if x != p {
				ps = append(ps, x)
			}
		}
		if len(ps) == 0 {
			continue
		}
		it.Passes = ps
		keep = append(keep, it)
	}
	if keep == nil {
		keep = []Item{}
	}
	m.Items = keep
}

func appendPass(ps []int, p int) []int {
	for _, x := range ps {
		if x == p {
			return ps
		}
	}
	return append(ps, p)
}

// stripLoopFields drops run_tag and seen from a record; Merge sets them.
func stripLoopFields(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	delete(m, "run_tag")
	delete(m, "seen")
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}

// cumulative builds findings.json from every item's latest record, with
// run_tag (NEW: first seen in the latest pass) and seen {passes, of}. The
// top-level fields come from the latest pass's document.
func (m *Memory) cumulative(latest []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(latest, &top); err != nil {
		return nil, err
	}
	ran := len(m.Passes)
	var recs []json.RawMessage
	for _, it := range m.Items {
		var r map[string]json.RawMessage
		if err := json.Unmarshal(it.Record, &r); err != nil {
			return nil, err
		}
		tag := "KNOWN"
		if it.FirstPass == ran {
			tag = "NEW"
		}
		r["run_tag"], _ = json.Marshal(tag)
		r["seen"], _ = json.Marshal(map[string]int{"passes": len(it.Passes), "of": ran})
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		recs = append(recs, b)
	}
	if recs == nil {
		recs = []json.RawMessage{}
	}
	top["records"], _ = json.Marshal(recs)
	if len(recs) > 0 {
		delete(top, "no_findings")
		delete(top, "no_findings_reason")
	}
	b, err := marshalIndent(top)
	if err != nil {
		return nil, err
	}
	rep, err := validate.Document("findings", b)
	if err != nil {
		return nil, err
	}
	if !rep.OK() {
		return nil, fmt.Errorf("memory merge: the cumulative findings.json would be invalid: %s", strings.Join(rep.Errors, "; "))
	}
	return b, nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Known renders the "already known" list a later pass's bundles inline.
func (m *Memory) Known() string {
	if len(m.Items) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Loop mode: %d of %d passes merged. These fingerprints are already in memory. Do not spend time re-deriving them. If your lens meets one again, write one line `KNOWN: <fingerprint> — <file:line> — still present` (or with new evidence, a full block that says what is new). Rejected items stay rejected unless you have evidence the refutation missed.\n\n", len(m.Passes), m.PassesPlanned)
	b.WriteString("| Fingerprint | Verdict | Title | Location | Seen |\n|---|---|---|---|---|\n")
	for _, it := range m.Items {
		fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` | %d/%d |\n", it.Fingerprint, it.Verdict, cell(it.Title), it.Location, len(it.Passes), len(m.Passes))
	}
	return b.String()
}

// Status renders the per-fingerprint table with "seen in k/N passes".
func (m *Memory) Status() string {
	var b strings.Builder
	fmt.Fprintf(&b, "passes: %d of %d merged", len(m.Passes), m.PassesPlanned)
	if n := len(m.Passes); n > 0 {
		last := m.Passes[n-1]
		state := "continue"
		if last.Stop {
			state = "stop"
		}
		fmt.Fprintf(&b, " · %s: %s", state, last.Reason)
	}
	b.WriteString("\n\n| Fingerprint | Verdict | Tag | Seen in |\n|---|---|---|---|\n")
	for _, it := range m.Items {
		tag := "KNOWN"
		if it.FirstPass == len(m.Passes) {
			tag = "NEW"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %d/%d passes |\n", it.Fingerprint, it.Verdict, tag, len(it.Passes), len(m.Passes))
	}
	return b.String()
}

func cell(s string) string { return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s) }

var reFence = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// MissingUnits counts the missing_units in a critic's return (raw JSON, or
// JSON in a fenced block).
func MissingUnits(b []byte) (int, error) {
	s := strings.TrimSpace(string(b))
	if m := reFence.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	var v struct {
		MissingUnits []json.RawMessage `json:"missing_units"`
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return 0, fmt.Errorf("critic output is not {\"missing_units\": [...]} JSON: %w", err)
	}
	return len(v.MissingUnits), nil
}
