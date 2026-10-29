// Package budget keeps a run's spend ledger (<out>/spend.json) and applies
// the --budget ceiling: before each wave of agents the orchestrator asks
// whether the estimated spend so far plus the wave's estimate stays under
// the budget, and stops the run when it does not.
//
// The Agent tool reports tokens for some agents (Claude Code appends
// `subagent_tokens`, `tool_uses` and `duration_ms` to a subagent's result)
// and cost for none, so spend is counted in tokens and converted to USD
// with the calibrated blended rate (internal/estimate). An agent whose
// tokens were not shown is counted at its role's calibrated average and
// marked "estimated". Every USD figure here is therefore an estimate.
package budget

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/estimate"
)

// File is the spend ledger's name in the output directory.
const File = "spend.json"

// Roles an agent can have.
var Roles = []string{"hunter", "poc", "refuter", "critic", "wave", "companion", "other"}

// Entry is one agent attempt.
type Entry struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	Tokens     int    `json:"tokens"`
	Source     string `json:"tokens_source"` // reported, estimated
	ToolUses   int    `json:"tool_uses,omitempty"`
	DurationMS int    `json:"duration_ms,omitempty"`
	Model      string `json:"model,omitempty"`
}

// Check is one `budget check` before a wave.
type Check struct {
	Before    string  `json:"before"`
	SpentUSD  float64 `json:"spent_usd"`
	NextUSD   float64 `json:"next_usd"`
	BudgetUSD float64 `json:"budget_usd"`
	Stop      bool    `json:"stop"`
}

// Stop records why the run ended early.
type Stop struct {
	Before    string  `json:"before"`
	SpentUSD  float64 `json:"spent_usd"`
	NextUSD   float64 `json:"next_usd"`
	BudgetUSD float64 `json:"budget_usd"`
	Reason    string  `json:"reason"`
}

// Ledger is spend.json.
type Ledger struct {
	SchemaVersion string  `json:"schema_version"`
	Profile       string  `json:"profile,omitempty"`
	BudgetUSD     float64 `json:"budget_usd,omitempty"`
	RateNote      string  `json:"rate"`
	Entries       []Entry `json:"entries"`
	Checks        []Check `json:"checks"`
	Stopped       *Stop   `json:"stopped,omitempty"`
}

// Load reads <out>/spend.json; ok is false when it does not exist.
func Load(out string) (*Ledger, bool, error) {
	b, err := os.ReadFile(filepath.Join(out, File))
	if os.IsNotExist(err) {
		return &Ledger{SchemaVersion: "1", Entries: []Entry{}, Checks: []Check{}}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, false, fmt.Errorf("%s: %w", File, err)
	}
	if l.Entries == nil {
		l.Entries = []Entry{}
	}
	if l.Checks == nil {
		l.Checks = []Check{}
	}
	return &l, true, nil
}

// Save writes <out>/spend.json atomically.
func (l *Ledger) Save(out string) error {
	c := estimate.Load()
	l.SchemaVersion = "1"
	l.RateNote = fmt.Sprintf("%.1f USD per million subagent tokens (blended, %s)", c.USDPerMTok.Mid, c.Source)
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(out, ".spend-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(out, File))
}

// RoleTokens is the calibrated tokens of one agent of a role in a profile.
func RoleTokens(role, profile string) int {
	c := estimate.Load()
	switch role {
	case "hunter", "companion", "other":
		return c.HunterTokens(profile, c.ReferenceSourceLines)
	case "poc":
		return c.Roles.PoC
	case "refuter":
		return c.Roles.Refuter
	case "critic":
		return c.Roles.Critic
	case "wave":
		return c.Roles.Wave
	}
	return c.HunterTokens(profile, c.ReferenceSourceLines)
}

// RoleOf guesses a role from an agent id: critics by name, the rest are
// hunters.
func RoleOf(id string) string {
	base := strings.SplitN(id, "@", 2)[0]
	switch {
	case base == "critic" || base == "coverage" || base == "final-clean":
		return "critic"
	case strings.HasPrefix(base, "poc"):
		return "poc"
	case strings.HasPrefix(base, "refuter"):
		return "refuter"
	}
	return "hunter"
}

// Record appends one agent attempt. tokens <= 0 means not reported: the
// role's calibrated average is used and the entry is marked estimated.
func (l *Ledger) Record(e Entry) error {
	if e.ID == "" {
		return fmt.Errorf("budget record: --id is required")
	}
	if e.Role == "" {
		e.Role = RoleOf(e.ID)
	}
	ok := false
	for _, r := range Roles {
		ok = ok || r == e.Role
	}
	if !ok {
		return fmt.Errorf("budget record: role %q (want %s)", e.Role, strings.Join(Roles, ", "))
	}
	if e.Status == "" {
		e.Status = "done"
	}
	if e.Tokens > 0 {
		e.Source = "reported"
	} else {
		e.Tokens, e.Source = RoleTokens(e.Role, l.Profile), "estimated"
	}
	e.Attempt = 1
	for _, x := range l.Entries {
		if x.ID == e.ID && x.Role == e.Role {
			e.Attempt = x.Attempt + 1
		}
	}
	l.Entries = append(l.Entries, e)
	return nil
}

// Totals sums the entries.
type Totals struct {
	Agents    int            `json:"agents"`
	Attempts  int            `json:"attempts"`
	Tokens    int            `json:"tokens"`
	Reported  int            `json:"tokens_reported"`
	Estimated int            `json:"tokens_estimated"`
	USD       float64        `json:"usd"`
	USDLow    float64        `json:"usd_low"`
	USDHigh   float64        `json:"usd_high"`
	ByRole    map[string]int `json:"agents_by_role"`
}

// Totals sums tokens and converts them with the calibrated rate.
func (l *Ledger) Totals() Totals {
	c := estimate.Load()
	t := Totals{ByRole: map[string]int{}}
	ids := map[string]bool{}
	for _, e := range l.Entries {
		t.Attempts++
		if !ids[e.Role+"/"+e.ID] {
			ids[e.Role+"/"+e.ID] = true
			t.Agents++
			t.ByRole[e.Role]++
		}
		t.Tokens += e.Tokens
		if e.Source == "reported" {
			t.Reported += e.Tokens
		} else {
			t.Estimated += e.Tokens
		}
	}
	m := float64(t.Tokens) / 1e6
	t.USD, t.USDLow, t.USDHigh = round2(m*c.USDPerMTok.Mid), round2(m*c.USDPerMTok.Low), round2(m*c.USDPerMTok.High)
	return t
}

// Wave is the agents of the next wave by role.
type Wave map[string]int

// Cost is the calibrated USD of a wave at the high rate (the check is
// conservative: it stops a little early rather than late).
func (w Wave) Cost(profile string) (int, float64) {
	c := estimate.Load()
	tok := 0
	for role, n := range w {
		tok += n * RoleTokens(role, profile)
	}
	return tok, round2(float64(tok) / 1e6 * c.USDPerMTok.High)
}

// Decision is the answer of `budget check`.
type Decision struct {
	Before       string  `json:"before"`
	SpentUSD     float64 `json:"spent_usd"`
	NextUSD      float64 `json:"next_usd"`
	NextTokens   int     `json:"next_tokens"`
	BudgetUSD    float64 `json:"budget_usd"`
	RemainingUSD float64 `json:"remaining_usd"`
	Stop         bool    `json:"stop"`
	Reason       string  `json:"reason"`
	Then         string  `json:"then,omitempty"`
}

// Check decides whether the next wave fits the budget and records the
// check; a stop is recorded in Stopped and is final (later checks stop too).
func (l *Ledger) Check(before string, w Wave, budget float64) Decision {
	if budget <= 0 {
		budget = l.BudgetUSD
	}
	t := l.Totals()
	tok, next := w.Cost(l.Profile)
	d := Decision{Before: before, SpentUSD: t.USD, NextUSD: next, NextTokens: tok, BudgetUSD: budget}
	switch {
	case l.Stopped != nil:
		d.Stop, d.Reason = true, "the run already stopped at the budget ceiling before "+l.Stopped.Before
	case budget <= 0:
		d.Reason = "no budget set (--budget USD); spend is recorded only"
	case t.USD+next > budget:
		d.Stop = true
		d.Reason = fmt.Sprintf("estimated spend %.2f USD plus %.2f USD for %s exceeds the budget of %.2f USD", t.USD, next, before, budget)
		l.Stopped = &Stop{Before: before, SpentUSD: t.USD, NextUSD: next, BudgetUSD: budget, Reason: d.Reason}
	default:
		d.Reason = fmt.Sprintf("estimated spend %.2f USD plus %.2f USD for %s stays within %.2f USD", t.USD, next, before, budget)
	}
	if budget > 0 {
		d.RemainingUSD = round2(math.Max(0, budget-t.USD))
	}
	if d.Stop {
		d.Then = `spawn nothing more; close the ledger (ledger mark --from planned --status deferred --reason "budget: ...", same for in_progress), judge what the saved agents returned and assemble: the report says it is partial`
	}
	l.Checks = append(l.Checks, Check{Before: before, SpentUSD: t.USD, NextUSD: next, BudgetUSD: budget, Stop: d.Stop})
	return d
}

// Summary is a one-line description for the report.
func (l *Ledger) Summary() string {
	t := l.Totals()
	var roles []string
	for r, n := range t.ByRole {
		roles = append(roles, fmt.Sprintf("%d %s", n, r))
	}
	sort.Strings(roles)
	s := fmt.Sprintf("about %.2f USD (range %.2f-%.2f) for %d agents (%s; %d attempts), %.2fM tokens of which %.2fM reported by the runtime and %.2fM estimated",
		t.USD, t.USDLow, t.USDHigh, t.Agents, strings.Join(roles, ", "), t.Attempts, float64(t.Tokens)/1e6, float64(t.Reported)/1e6, float64(t.Estimated)/1e6)
	if l.BudgetUSD > 0 {
		s += fmt.Sprintf("; budget %.2f USD", l.BudgetUSD)
	}
	return s
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
