package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Key is a case's machine-readable answer key (evals/cases/<case>/key.json).
// Items are located by code anchors instead of line numbers, so the key works
// on the sanitized copy, whose line numbers differ from the fixture's.
type Key struct {
	SchemaVersion string  `json:"schema_version"`
	Case          string  `json:"case"`
	Fixture       string  `json:"fixture"`
	Items         []*Item `json:"items"`
	Decoys        []*Item `json:"decoys"`
	Other         []*Item `json:"other"`
}

// Item is one planted bug, decoy or other true observation.
type Item struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Ranges []Range `json:"ranges"`
	Match  string  `json:"match"`
	// MatchIn "title" applies Match to the title, bug class and fingerprint
	// only, for items whose words also appear in other findings' prose.
	MatchIn  string   `json:"match_in"`
	Expect   []string `json:"expect"`
	Partial  []string `json:"partial"`
	Severity []string `json:"severity"`
	Critical bool     `json:"critical"`
	// Class tags the item for per-class recall (soundness, integration,
	// trusted-party, privacy, liveness, dependency, setup, hygiene).
	Class string `json:"class"`

	re       *regexp.Regexp
	resolved []span
}

// Range is a file region bounded by the first and last of its anchors. Each
// anchor is searched for after the line of the previous one.
type Range struct {
	File    string   `json:"file"`
	Anchors []string `json:"anchors"`
	// Lines is [first, last], 1-based, for keys built from a human report
	// on an unmodified tree (pilots), where line numbers are stable. It
	// takes precedence over Anchors.
	Lines []int `json:"lines,omitempty"`
}

type span struct {
	file       string
	start, end int
}

// slack is how many lines outside an item's range a record may point at and
// still count as the same place.
const slack = 3

func loadKey(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k Key
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&k); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if k.SchemaVersion != "1" {
		return nil, fmt.Errorf("%s: schema_version %q, want \"1\"", path, k.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, it := range k.all() {
		if it.ID == "" || seen[it.ID] {
			return nil, fmt.Errorf("%s: missing or duplicate item id %q", path, it.ID)
		}
		seen[it.ID] = true
		if len(it.Ranges) == 0 {
			return nil, fmt.Errorf("%s: item %s has no ranges", path, it.ID)
		}
		if it.MatchIn != "" && it.MatchIn != "title" {
			return nil, fmt.Errorf("%s: item %s: match_in %q, want \"title\" or empty", path, it.ID, it.MatchIn)
		}
		if it.Match != "" {
			if it.re, err = regexp.Compile(it.Match); err != nil {
				return nil, fmt.Errorf("%s: item %s: %w", path, it.ID, err)
			}
		}
		for _, v := range append(append([]string{}, it.Expect...), it.Partial...) {
			if _, ok := rank[v]; !ok {
				return nil, fmt.Errorf("%s: item %s: unknown verdict class %q", path, it.ID, v)
			}
		}
	}
	return &k, nil
}

func (k *Key) all() []*Item {
	out := append([]*Item{}, k.Items...)
	out = append(out, k.Decoys...)
	return append(out, k.Other...)
}

// resolve finds every anchor in the audited tree. A missing anchor is an
// error: the key and the fixture have drifted.
func (k *Key) resolve(target string) error {
	cache := map[string][]string{}
	for _, it := range k.all() {
		it.resolved = nil
		for _, r := range it.Ranges {
			lines, ok := cache[r.File]
			if !ok {
				b, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(r.File)))
				if err != nil {
					return fmt.Errorf("item %s: %w", it.ID, err)
				}
				lines = strings.Split(string(b), "\n")
				cache[r.File] = lines
			}
			if len(r.Lines) > 0 {
				if len(r.Lines) != 2 || r.Lines[0] < 1 || r.Lines[1] < r.Lines[0] || r.Lines[1] > len(lines) {
					return fmt.Errorf("item %s: lines %v are not a range inside %s (%d lines)", it.ID, r.Lines, r.File, len(lines))
				}
				it.resolved = append(it.resolved, span{r.File, r.Lines[0], r.Lines[1]})
				continue
			}
			if len(r.Anchors) == 0 {
				it.resolved = append(it.resolved, span{r.File, 1, len(lines)})
				continue
			}
			from, start, end := 0, 0, 0
			for i, a := range r.Anchors {
				n := find(lines, a, from)
				if n < 0 {
					return fmt.Errorf("item %s: anchor %q not found in %s", it.ID, a, r.File)
				}
				if i == 0 {
					start = n + 1
				}
				end = n + 1
				from = n + 1
			}
			it.resolved = append(it.resolved, span{r.File, start, end})
		}
	}
	return nil
}

func find(lines []string, anchor string, from int) int {
	for i := from; i < len(lines); i++ {
		if strings.Contains(lines[i], anchor) {
			return i
		}
	}
	return -1
}
