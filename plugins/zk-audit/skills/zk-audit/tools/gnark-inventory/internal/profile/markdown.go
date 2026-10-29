package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Generated regions. Each doc holds one begin/end marker pair; SyncDocs
// rewrites what lies between them and a test fails when a region drifts
// from the embedded profiles.json.
const (
	beginFmt = "<!-- generated:%s from profiles.json (make sync-profiles); do not edit -->"
	endFmt   = "<!-- end generated:%s -->"
)

// Region is one generated part of a skill doc.
type Region struct {
	File   string // relative to the skill directory
	Name   string
	Render func(*Set) string
}

// Regions lists every generated region.
var Regions = []Region{
	{"SKILL.md", "profile-table", (*Set).ProfileTable},
	{"references/orchestration.md", "agent-table", (*Set).AgentTable},
}

// ProfileTable is the profile table of SKILL.md §2.
func (s *Set) ProfileTable() string {
	var b strings.Builder
	b.WriteString("| Profile | Agents | PoC | Critics | Passes |\n|---|---|---|---|---|\n")
	for _, p := range s.Profiles {
		name := "`" + p.ID + "`"
		if p.Default {
			name += " (default)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", name, s.agentsCell(p.ID), p.PoC.Text, s.criticsCell(&p), passesCell(&p))
	}
	return b.String()
}

func (s *Set) agentsCell(profile string) string {
	var ids []string
	v := 0
	for _, l := range s.LensesFor(profile) {
		if l.IsVectorScan() {
			v++
			continue
		}
		ids = append(ids, l.ID)
	}
	cell := strings.Join(ids, ", ")
	if v > 0 {
		cell += fmt.Sprintf(" + %d vector-scan shards (V-*)", v)
	}
	return cell
}

func (s *Set) criticsCell(p *Profile) string {
	var parts []string
	for _, id := range p.Critics {
		for _, c := range s.Critics {
			if c.ID == id {
				parts = append(parts, c.Name)
			}
		}
	}
	if p.TargetedWaves > 0 {
		w := "wave"
		if p.TargetedWaves > 1 {
			w = "waves"
		}
		parts = append(parts, fmt.Sprintf("%d targeted %s", p.TargetedWaves, w))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " + ")
}

func passesCell(p *Profile) string {
	if p.Memory {
		return fmt.Sprintf("%d with memory", p.Passes)
	}
	return fmt.Sprint(p.Passes)
}

// AgentTable is the agent table of references/orchestration.md.
func (s *Set) AgentTable() string {
	var b strings.Builder
	b.WriteString("| Id | Lens | Lens file | Group | Shard | Profiles |\n|---|---|---|---|---|---|\n")
	for _, l := range s.Lenses {
		file := "`" + l.File + "`"
		if l.Slice != "" {
			file += " + `" + l.Slice + "`"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", l.ID, l.Name, file, l.Group, l.Shard, strings.Join(l.Profiles, ", "))
	}
	b.WriteString("\n")
	for _, p := range s.Profiles {
		fmt.Fprintf(&b, "- **%s**: %s.\n", p.ID, s.agentsCell(p.ID))
	}
	return b.String()
}

// SyncDocs compares (write=false) or rewrites (write=true) every generated
// region under skill. It returns the regions that differ (before writing).
func (s *Set) SyncDocs(skill string, write bool) ([]string, error) {
	var drift []string
	for _, r := range Regions {
		p := filepath.Join(skill, filepath.FromSlash(r.File))
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		doc := string(b)
		begin, end := fmt.Sprintf(beginFmt, r.Name), fmt.Sprintf(endFmt, r.Name)
		i := strings.Index(doc, begin)
		j := strings.Index(doc, end)
		if i < 0 || j < i {
			return nil, fmt.Errorf("%s: generated region %q markers not found", r.File, r.Name)
		}
		want := doc[:i] + begin + "\n\n" + r.Render(s) + "\n" + doc[j:]
		if want == doc {
			continue
		}
		drift = append(drift, r.File+" ("+r.Name+")")
		if write {
			if err := os.WriteFile(p, []byte(want), 0o644); err != nil {
				return nil, err
			}
		}
	}
	return drift, nil
}
