package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Load reads a ledger file.
func Load(path string) (*Ledger, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l Ledger
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range l.Units {
		u := &l.Units[i]
		for _, p := range []*[]string{&u.AgentIDs, &u.ReviewedPaths, &u.ResultFingerprints} {
			if *p == nil {
				*p = []string{}
			}
		}
	}
	return &l, nil
}

// Marshal renders the ledger as indented JSON.
func (l *Ledger) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteAtomic writes b to path through a temporary file and a rename.
func WriteAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ledger-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Selector picks units. Every non-empty field must match.
type Selector struct {
	IDs   []string // exact unit ids
	Match string   // substring of the id
	Lens  string   // a lens listed on the unit
	Kind  string   // unit kind
	Class string   // unit class
	// Status limits the selection to units in this status (e.g. planned).
	Status string
}

func (s Selector) empty() bool {
	return len(s.IDs) == 0 && s.Match == "" && s.Lens == "" && s.Kind == "" && s.Class == "" && s.Status == ""
}

func (s Selector) matches(u *Unit) bool {
	if len(s.IDs) > 0 && !contains(s.IDs, u.ID) {
		return false
	}
	if s.Match != "" && !strings.Contains(u.ID, s.Match) {
		return false
	}
	if s.Lens != "" && !contains(u.Lenses, s.Lens) {
		return false
	}
	if s.Kind != "" && u.Kind != s.Kind {
		return false
	}
	if s.Class != "" && u.Class != s.Class {
		return false
	}
	if s.Status != "" && u.Status != s.Status {
		return false
	}
	return true
}

// Change is what Mark applies to every selected unit.
type Change struct {
	Status       string
	Agents       []string // appended, unique
	Reviewed     []string // appended, unique
	Fingerprints []string // appended, unique
	Reason       string   // replaces the reason when set
	Notes        string   // replaces the notes when set
	Wave         int      // replaces the wave when > 0
}

// Mark applies c to the units sel selects and returns their ids. Selecting
// nothing is an error, so a typo never passes silently.
func (l *Ledger) Mark(sel Selector, c Change) ([]string, error) {
	if sel.empty() {
		return nil, fmt.Errorf("ledger mark: select units with --unit, --match, --lens, --kind, --class or --from")
	}
	var ids []string
	for i := range l.Units {
		u := &l.Units[i]
		if !sel.matches(u) {
			continue
		}
		if c.Status != "" {
			u.Status = c.Status
		}
		u.AgentIDs = appendUniq(u.AgentIDs, c.Agents...)
		u.ReviewedPaths = appendUniq(u.ReviewedPaths, c.Reviewed...)
		u.ResultFingerprints = appendUniq(u.ResultFingerprints, c.Fingerprints...)
		if c.Reason != "" {
			u.Reason = c.Reason
		}
		if c.Notes != "" {
			u.Notes = c.Notes
		}
		if c.Wave > 0 {
			u.Wave = c.Wave
		}
		ids = append(ids, u.ID)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("ledger mark: no unit matches the selection")
	}
	return ids, nil
}

// Add appends a unit the seeder did not create (one a critic found). Its id
// is <kind>:<subject>|<class>; an existing id is an error.
func (l *Ledger) Add(u Unit) (string, error) {
	u.ID = u.Kind + ":" + safe(u.Subject) + "|" + u.Class
	for _, x := range l.Units {
		if x.ID == u.ID {
			return "", fmt.Errorf("ledger add: unit %s already exists", u.ID)
		}
	}
	if u.Status == "" {
		u.Status = "planned"
	}
	for _, p := range []*[]string{&u.AgentIDs, &u.ReviewedPaths, &u.ResultFingerprints} {
		if *p == nil {
			*p = []string{}
		}
	}
	l.Units = append(l.Units, u)
	return u.ID, nil
}

// Counts returns the number of units per status, sorted by status name.
func (l *Ledger) Counts() []string {
	m := map[string]int{}
	for _, u := range l.Units {
		m[u.Status]++
	}
	var out []string
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func appendUniq(xs []string, add ...string) []string {
	for _, a := range add {
		if a != "" && !contains(xs, a) {
			xs = append(xs, a)
		}
	}
	return xs
}
