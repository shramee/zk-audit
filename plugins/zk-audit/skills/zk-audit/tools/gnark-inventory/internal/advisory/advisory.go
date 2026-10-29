// Package advisory holds the embedded gnark and gnark-crypto advisory table
// and the version matching used by `detect` and `advisories`.
package advisory

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

//go:embed advisories.json
var raw []byte

// Module paths the table covers.
const (
	Gnark       = "github.com/consensys/gnark"
	GnarkCrypto = "github.com/consensys/gnark-crypto"
)

// Range is one affected range [Introduced, Fixed); Introduced "0" means
// every version before Fixed.
type Range struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// Advisory is one row of the advisory table.
type Advisory struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	// Package is the Go module the advisory is published for: gnark or
	// gnark-crypto.
	Package    string `json:"package"`
	Severity   string `json:"severity"`
	Class      string `json:"class"`
	Component  string `json:"component"`
	Summary    string `json:"summary"`
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	// ExtraRanges are further affected ranges after [Introduced, Fixed)
	// (a fix backported to an older minor line leaves two ranges).
	ExtraRanges    []Range `json:"extra_ranges,omitempty"`
	Action         string  `json:"action"`
	RegenerateKeys bool    `json:"regenerate_keys"`
	URL            string  `json:"url"`
	// Verified is true when the affected range was checked against a
	// source that could be read: VerifiedBy names it ("osv": the OSV
	// record; "source": the fix located in the released source of the
	// module, the advisory text itself not being reachable).
	Verified   bool   `json:"verified"`
	VerifiedBy string `json:"verified_by,omitempty"`
	// Evidence says what was checked and where.
	Evidence string `json:"evidence,omitempty"`
}

// Table is the whole embedded document.
type Table struct {
	SchemaVersion string `json:"schema_version"`
	// AsOf is the date the table was last compared with its sources.
	AsOf       string     `json:"as_of"`
	Packages   []string   `json:"packages"`
	Sources    []string   `json:"sources"`
	Advisories []Advisory `json:"advisories"`
}

// Raw returns the embedded JSON bytes.
func Raw() []byte { return raw }

// Load parses the embedded table.
func Load() (*Table, error) {
	return Parse(raw)
}

// Parse parses an advisory table document.
func Parse(b []byte) (*Table, error) {
	var t Table
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("advisory table: %w", err)
	}
	if len(t.Advisories) == 0 {
		return nil, fmt.Errorf("advisory table: no advisories")
	}
	if t.AsOf == "" {
		return nil, fmt.Errorf("advisory table: as_of is required")
	}
	pkgs := map[string]bool{}
	for _, p := range t.Packages {
		pkgs[p] = true
	}
	seen := map[string]bool{}
	for _, a := range t.Advisories {
		if a.ID == "" || a.Fixed == "" || a.URL == "" || !pkgs[a.Package] || seen[a.ID] {
			return nil, fmt.Errorf("advisory table: incomplete or duplicate row %q (id, package from packages, fixed and url are required)", a.ID)
		}
		seen[a.ID] = true
		if a.Verified != (a.VerifiedBy != "") {
			return nil, fmt.Errorf("advisory %s: verified and verified_by go together", a.ID)
		}
		for _, r := range a.Ranges() {
			if r.Introduced != "0" {
				if _, err := ParseVersion(r.Introduced); err != nil {
					return nil, fmt.Errorf("advisory %s introduced: %w", a.ID, err)
				}
			}
			if _, err := ParseVersion(r.Fixed); err != nil {
				return nil, fmt.Errorf("advisory %s fixed: %w", a.ID, err)
			}
		}
	}
	return &t, nil
}

// Ranges returns every affected range of the advisory.
func (a Advisory) Ranges() []Range {
	return append([]Range{{Introduced: a.Introduced, Fixed: a.Fixed}}, a.ExtraRanges...)
}

// Affected renders the ranges as ">= v0.12.0, < v0.13.0; …".
func (a Advisory) Affected() string {
	var parts []string
	for _, r := range a.Ranges() {
		if r.Introduced == "0" || r.Introduced == "" {
			parts = append(parts, "< "+r.Fixed)
		} else {
			parts = append(parts, ">= "+r.Introduced+", < "+r.Fixed)
		}
	}
	return strings.Join(parts, "; ")
}

// Match is the result of checking one version against one advisory.
type Match struct {
	Advisory
	// Status is "affected", "possibly_affected" (version unknown) or
	// "not_affected".
	Status string `json:"status"`
}

// Affecting returns every gnark advisory that affects version, or every
// gnark advisory with status possibly_affected when the version cannot be
// parsed.
func (t *Table) Affecting(version string) []Match {
	return t.AffectingModule(Gnark, version)
}

// AffectingModule is Affecting for the advisories of one module (Gnark or
// GnarkCrypto).
func (t *Table) AffectingModule(module, version string) []Match {
	var out []Match
	v, err := ParseVersion(version)
	for _, a := range t.Advisories {
		if a.Package != module {
			continue
		}
		if err != nil {
			out = append(out, Match{Advisory: a, Status: "possibly_affected"})
			continue
		}
		if a.Affects(v) {
			out = append(out, Match{Advisory: a, Status: "affected"})
		}
	}
	return out
}

// Affects reports whether v is in one of the advisory's ranges.
func (a Advisory) Affects(v Version) bool {
	for _, r := range a.Ranges() {
		if r.Affects(v) {
			return true
		}
	}
	return false
}

// Affects reports whether v is in [Introduced, Fixed).
func (r Range) Affects(v Version) bool {
	fixed, err := ParseVersion(r.Fixed)
	if err != nil {
		return true
	}
	if Compare(v, fixed) >= 0 {
		return false
	}
	if r.Introduced == "0" || r.Introduced == "" {
		return true
	}
	intro, err := ParseVersion(r.Introduced)
	if err != nil {
		return true
	}
	return Compare(v, intro) >= 0
}

// Version is a parsed semantic version (Go module flavour).
type Version struct {
	Major, Minor, Patch int
	Pre                 []string
	Original            string
}

// ParseVersion parses vMAJOR.MINOR.PATCH[-pre][+build]. Go pseudo-versions
// parse as pre-releases, which orders them correctly against tags.
func ParseVersion(s string) (Version, error) {
	orig := s
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return Version{}, fmt.Errorf("version %q: missing v prefix", orig)
	}
	s = s[1:]
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q: want vX.Y.Z", orig)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("version %q: bad number %q", orig, p)
		}
		nums[i] = n
	}
	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Original: orig}
	if pre != "" {
		v.Pre = strings.Split(pre, ".")
	}
	return v, nil
}

// Compare returns -1, 0 or +1.
func Compare(a, b Version) int {
	for _, d := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		if c := comparePre(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

func comparePre(x, y string) int {
	xn, xerr := strconv.Atoi(x)
	yn, yerr := strconv.Atoi(y)
	switch {
	case xerr == nil && yerr == nil:
		if xn < yn {
			return -1
		} else if xn > yn {
			return 1
		}
		return 0
	case xerr == nil:
		return -1
	case yerr == nil:
		return 1
	}
	return strings.Compare(x, y)
}
