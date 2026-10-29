package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultOSV is the OSV API the freshness check queries. It is only
// contacted by `advisories --osv`, which the user must approve (network).
const DefaultOSV = "https://api.osv.dev"

// OSVVuln is the part of an OSV record the freshness check reads.
type OSVVuln struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Modified string        `json:"modified"`
	Affected []OSVAffected `json:"affected"`
}

// OSVAffected is one affected package of an OSV record.
type OSVAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

// RangesFor returns the record's affected ranges for module, as Go module
// versions ("v" prefix), deduplicated and sorted.
func (v OSVVuln) RangesFor(module string) []Range {
	seen := map[Range]bool{}
	var out []Range
	for _, a := range v.Affected {
		if a.Package.Name != module {
			continue
		}
		for _, r := range a.Ranges {
			var cur *Range
			for _, ev := range r.Events {
				if x, ok := ev["introduced"]; ok {
					cur = &Range{Introduced: goVersion(x)}
				}
				if x, ok := ev["fixed"]; ok && cur != nil {
					cur.Fixed = goVersion(x)
					if !seen[*cur] {
						seen[*cur] = true
						out = append(out, *cur)
					}
					cur = nil
				}
			}
			if cur != nil && !seen[*cur] { // no fix yet
				seen[*cur] = true
				out = append(out, *cur)
			}
		}
	}
	sortRanges(out)
	return out
}

func goVersion(s string) string {
	if s == "0" || s == "" || strings.HasPrefix(s, "v") {
		return s
	}
	return "v" + s
}

func sortRanges(rs []Range) {
	sort.Slice(rs, func(i, j int) bool {
		a, ea := ParseVersion(rs[i].Fixed)
		b, eb := ParseVersion(rs[j].Fixed)
		if ea != nil || eb != nil {
			return rs[i].Fixed < rs[j].Fixed
		}
		return Compare(a, b) < 0
	})
}

func rangesString(rs []Range) string {
	a := Advisory{}
	if len(rs) == 0 {
		return "(none)"
	}
	a.Introduced, a.Fixed, a.ExtraRanges = rs[0].Introduced, rs[0].Fixed, rs[1:]
	if a.Fixed == "" {
		return ">= " + a.Introduced + " (no fix)"
	}
	return a.Affected()
}

// OSV is a minimal OSV API client.
type OSV struct {
	BaseURL string
	HTTP    *http.Client
}

// NewOSV returns a client for base (DefaultOSV when empty) with a 20 s
// time limit per request.
func NewOSV(base string) *OSV {
	if base == "" {
		base = DefaultOSV
	}
	return &OSV{BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// Query returns the OSV records that affect module at version.
func (c *OSV) Query(ctx context.Context, module, version string) ([]OSVVuln, error) {
	var all []OSVVuln
	token := ""
	for page := 0; page < 20; page++ {
		q := map[string]any{"package": map[string]string{"name": module, "ecosystem": "Go"}, "version": version}
		if token != "" {
			q["page_token"] = token
		}
		body, _ := json.Marshal(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/query", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		var res struct {
			Vulns         []OSVVuln `json:"vulns"`
			NextPageToken string    `json:"next_page_token"`
		}
		if _, err := c.do(req, &res); err != nil {
			return nil, fmt.Errorf("osv query %s@%s: %w", module, version, err)
		}
		all = append(all, res.Vulns...)
		if res.NextPageToken == "" {
			return all, nil
		}
		token = res.NextPageToken
	}
	return all, nil
}

// Get returns one OSV record; found is false when OSV does not have it.
func (c *OSV) Get(ctx context.Context, id string) (*OSVVuln, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, false, err
	}
	var v OSVVuln
	code, err := c.do(req, &v)
	if code == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("osv get %s: %w", id, err)
	}
	return &v, true, nil
}

func (c *OSV) do(req *http.Request, into any) (int, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b[:min(len(b), 200)])))
	}
	return resp.StatusCode, json.Unmarshal(b, into)
}

// Freshness is the result of `advisories --osv`.
type Freshness struct {
	TableAsOf string      `json:"table_as_of"`
	Checked   string      `json:"checked"`
	Source    string      `json:"source"`
	Queried   []Queried   `json:"queried"`
	New       []NewID     `json:"new"`
	Changed   []ChangedID `json:"changed"`
	NotInOSV  []NotInOSV  `json:"not_in_osv"`
	Summary   string      `json:"summary"`
}

// Queried is one module version sent to OSV and the ids it returned.
type Queried struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	OSVIDs  []string `json:"osv_ids"`
}

// NewID is an OSV record affecting the pinned version that no table row
// (by id or alias) covers.
type NewID struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Affected string   `json:"affected"`
	Summary  string   `json:"summary"`
	Modified string   `json:"modified"`
}

// ChangedID is a table row whose affected ranges differ from OSV's.
type ChangedID struct {
	ID      string `json:"id"`
	OSVID   string `json:"osv_id"`
	Package string `json:"package"`
	Version string `json:"version"`
	Table   string `json:"table"`
	OSV     string `json:"osv"`
}

// NotInOSV is a table row that affects the pinned version but that OSV does
// not have at all.
type NotInOSV struct {
	ID         string `json:"id"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	VerifiedBy string `json:"verified_by"`
}

// Lookup fetches one OSV record by id (OSV.Get).
type Lookup func(id string) (*OSVVuln, bool, error)

// CompareOSV diffs what OSV returned for module@version against the table.
// lookup resolves table rows that affect the version but were not returned,
// to tell "OSV does not have it" from "OSV has a different range".
func (t *Table) CompareOSV(f *Freshness, module, version string, osv []OSVVuln, lookup Lookup) error {
	q := Queried{Package: module, Version: version, OSVIDs: []string{}}
	byID := map[string]*Advisory{}
	for i := range t.Advisories {
		a := &t.Advisories[i]
		if a.Package != module {
			continue
		}
		byID[a.ID] = a
		for _, al := range a.Aliases {
			byID[al] = a
		}
	}
	for _, v := range osv {
		q.OSVIDs = append(q.OSVIDs, v.ID)
	}
	sort.Strings(q.OSVIDs)
	f.Queried = append(f.Queried, q)
	covered := map[string]bool{} // table ids OSV returned a record for
	compared := map[string]bool{}
	// the row's own record first, then alias records (GO-…) for rows whose
	// own record was not returned
	var sorted []OSVVuln
	for pass := 0; pass < 2; pass++ {
		for _, v := range osv {
			own := byID[v.ID] != nil && byID[v.ID].ID == v.ID
			if own == (pass == 0) {
				sorted = append(sorted, v)
			}
		}
	}
	for _, v := range sorted {
		row := byID[v.ID]
		if row == nil {
			for _, al := range v.Aliases {
				if r := byID[al]; r != nil {
					row = r
					break
				}
			}
		}
		if row == nil {
			f.New = append(f.New, NewID{ID: v.ID, Aliases: nonNil(v.Aliases), Package: module, Version: version,
				Affected: rangesString(v.RangesFor(module)), Summary: v.Summary, Modified: v.Modified})
			continue
		}
		covered[row.ID] = true
		if compared[row.ID] {
			continue
		}
		compared[row.ID] = true
		if got, want := v.RangesFor(module), row.Ranges(); !sameRanges(got, want) {
			f.Changed = append(f.Changed, ChangedID{ID: row.ID, OSVID: v.ID, Package: module, Version: version,
				Table: rangesString(want), OSV: rangesString(got)})
		}
	}
	// rows the table says affect this version that OSV did not return
	pv, err := ParseVersion(version)
	if err != nil {
		return err
	}
	var ids []string
	for id, a := range byID {
		if id == a.ID && !covered[a.ID] && a.Affects(pv) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := byID[id]
		var rec *OSVVuln
		found := false
		for _, cand := range append([]string{a.ID}, a.Aliases...) {
			r, ok, err := lookup(cand)
			if err != nil {
				return err
			}
			if ok {
				rec, found = r, true
				break
			}
		}
		if !found {
			f.NotInOSV = append(f.NotInOSV, NotInOSV{ID: a.ID, Package: module, Version: version, VerifiedBy: a.VerifiedBy})
			continue
		}
		f.Changed = append(f.Changed, ChangedID{ID: a.ID, OSVID: rec.ID, Package: module, Version: version,
			Table: rangesString(a.Ranges()), OSV: rangesString(rec.RangesFor(module))})
	}
	return nil
}

// Finish sets the summary line.
func (f *Freshness) Finish() {
	if f.New == nil {
		f.New = []NewID{}
	}
	if f.Changed == nil {
		f.Changed = []ChangedID{}
	}
	if f.NotInOSV == nil {
		f.NotInOSV = []NotInOSV{}
	}
	var qs []string
	for _, q := range f.Queried {
		qs = append(qs, fmt.Sprintf("%s@%s", shortModule(q.Package), q.Version))
	}
	f.Summary = fmt.Sprintf("advisory table as of %s vs %s (%s) on %s: %d new id(s), %d changed range(s), %d table row(s) not in OSV",
		f.TableAsOf, f.Source, strings.Join(qs, ", "), f.Checked, len(f.New), len(f.Changed), len(f.NotInOSV))
}

func shortModule(m string) string {
	return strings.TrimPrefix(m, "github.com/consensys/")
}

func sameRanges(a, b []Range) bool {
	a2 := append([]Range{}, a...)
	b2 := append([]Range{}, b...)
	sortRanges(a2)
	sortRanges(b2)
	if len(a2) != len(b2) {
		return false
	}
	for i := range a2 {
		ia, ib := a2[i].Introduced, b2[i].Introduced
		if ia == "" {
			ia = "0"
		}
		if ib == "" {
			ib = "0"
		}
		if ia != ib || a2[i].Fixed != b2[i].Fixed {
			return false
		}
	}
	return true
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
