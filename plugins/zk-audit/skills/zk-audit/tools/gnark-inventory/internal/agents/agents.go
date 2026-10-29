// Package agents saves hunter, critic and wave outputs under <out>/agents/
// and keeps an index of every agent's status, so the orchestrator never
// hand-writes these files and the ledger checks can find them.
package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// Statuses an agent can end in.
var Statuses = map[string]bool{"done": true, "blocked": true, "failed": true, "refused": true}

// Entry is one agent of agents/index.json.
type Entry struct {
	ID       string `json:"id"`
	File     string `json:"file,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
	Leads    int    `json:"leads"`
	Bytes    int    `json:"bytes"`
	Attempts int    `json:"attempts"`
	// Model is the model the runtime ran the agent on, when it said so
	// (a fallback to another model is recorded here and in the reason).
	Model string `json:"model,omitempty"`
}

// Index is agents/index.json.
type Index struct {
	Agents []Entry `json:"agents"`
}

var (
	reFinding = regexp.MustCompile(`(?m)^[ \t>*_]*FINDING[ \t]*\|`)
	reLead    = regexp.MustCompile(`(?m)^[ \t>*_]*LEAD[ \t]*\|`)
	reID      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*(@[A-Za-z0-9_./-]+)?$`)
)

// Save writes an agent's raw return to <out>/agents/<id>.md (for status
// done, or whenever content is given) and records the agent in the index.
// A blocked, failed or refused agent needs a reason; saving the same id again
// counts another attempt and replaces the output.
func Save(out, id, content, status, reason string) (*Entry, error) {
	return SaveWith(out, id, content, status, reason, "")
}

// SaveWith is Save that also records the model the agent ran on.
func SaveWith(out, id, content, status, reason, model string) (*Entry, error) {
	if !reID.MatchString(id) || strings.Contains(id, "..") {
		return nil, fmt.Errorf("agents save: %q is not an agent id", id)
	}
	if !Statuses[status] {
		return nil, fmt.Errorf("agents save: status %q (want done, blocked, failed or refused)", status)
	}
	if status != "done" && strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("agents save: status %s needs --reason", status)
	}
	if status == "done" && strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("agents save: empty output for %s; an agent with nothing to report returns `no findings: <what it read>`", id)
	}
	dir := filepath.Join(out, "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	idx, err := Load(out)
	if err != nil {
		return nil, err
	}
	e := Entry{ID: id, Status: status, Reason: reason, Bytes: len(content), Model: model,
		Findings: len(reFinding.FindAllStringIndex(content, -1)), Leads: len(reLead.FindAllStringIndex(content, -1))}
	if strings.TrimSpace(content) != "" {
		e.File = "agents/" + validate.SafeName(id) + ".md"
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(filepath.Join(out, filepath.FromSlash(e.File)), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	found := false
	for i := range idx.Agents {
		if idx.Agents[i].ID == id {
			e.Attempts = idx.Agents[i].Attempts + 1
			idx.Agents[i] = e
			found = true
		}
	}
	if !found {
		e.Attempts = 1
		idx.Agents = append(idx.Agents, e)
	}
	sort.Slice(idx.Agents, func(i, j int) bool { return idx.Agents[i].ID < idx.Agents[j].ID })
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), append(b, '\n'), 0o644); err != nil {
		return nil, err
	}
	return &e, nil
}

// Load reads <out>/agents/index.json (empty when absent).
func Load(out string) (*Index, error) {
	b, err := os.ReadFile(filepath.Join(out, "agents", "index.json"))
	if os.IsNotExist(err) {
		return &Index{Agents: []Entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("agents/index.json: %w", err)
	}
	return &idx, nil
}
