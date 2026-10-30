// Package status reads an audit output directory and reports how far the
// run got: which steps are done, which agents were saved, failed or never
// ran, what the ledger still has open, the loop memory, the spend and the
// report. `/zk-audit resume` uses it to restart at the first incomplete step
// without redoing agents whose output is saved.
package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/agents"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/args"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/budget"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/ledger"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/memory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Step is one step of the run.
type Step struct {
	Phase  string `json:"phase"` // the SKILL.md phase (0 Detect ... 6 Report)
	Name   string `json:"name"`
	State  string `json:"state"` // done, partial, todo, skipped
	Detail string `json:"detail,omitempty"`
	Action string `json:"action,omitempty"` // what to do when the step is not done
}

// Agents groups the planned agents of the current hunt by state.
type Agents struct {
	Planned []string `json:"planned"`
	Done    []string `json:"done"`
	Missing []string `json:"missing"`
	Retry   []string `json:"retry"`   // failed or refused once: retry once with plain wording
	Blocked []string `json:"blocked"` // blocked, or failed twice: record, do not retry
	Extra   []string `json:"extra"`   // saved outputs no bundle names (critics, waves, earlier passes)
}

// Status is the state of one output directory.
type Status struct {
	Out       string         `json:"out"`
	RunID     string         `json:"run_id,omitempty"`
	Profile   string         `json:"profile,omitempty"`
	Passes    int            `json:"passes"`
	PoC       bool           `json:"poc"`
	Pass      int            `json:"current_pass"`
	RunFile   bool           `json:"run_json"`
	Steps     []Step         `json:"steps"`
	Agents    Agents         `json:"agents"`
	Ledger    map[string]int `json:"ledger_counts,omitempty"`
	Open      int            `json:"ledger_open"`
	Spend     string         `json:"spend,omitempty"`
	Stopped   string         `json:"budget_stop,omitempty"`
	Report    bool           `json:"report"`
	Next      string         `json:"next"`
	NextPhase string         `json:"next_phase"`
	Complete  bool           `json:"complete"`
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mtime(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.ModTime().UnixNano()
}

type bundleRow struct {
	Agent  string `json:"agent"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// Read builds the status of out.
func Read(out string) (*Status, error) {
	st, err := os.Stat(out)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("status: %s is not an output directory", out)
	}
	s := &Status{Out: out, Passes: 1, PoC: true, Pass: 1}
	at := func(p ...string) string { return filepath.Join(append([]string{out}, p...)...) }
	add := func(phase, name string, done bool, partial bool, detail, action string) {
		state := "todo"
		switch {
		case done:
			state = "done"
		case partial:
			state = "partial"
		}
		if done {
			action = ""
		}
		s.Steps = append(s.Steps, Step{Phase: phase, Name: name, State: state, Detail: detail, Action: action})
	}

	// the invocation
	if r, err := args.Load(out); err == nil {
		s.RunFile = true
		s.RunID, s.Profile, s.Passes, s.PoC = r.RunID, r.Profile, r.Passes, r.PoC
	}
	var led *ledger.Ledger
	if l, err := ledger.Load(at("coverage-ledger.json")); err == nil {
		led = l
		if s.RunID == "" {
			s.RunID = l.RunID
		}
		if s.Profile == "" {
			s.Profile = l.Profile
		}
	}
	prof, profOK := profile.Load().Profile(s.Profile)
	if profOK && !s.RunFile {
		s.Passes = prof.Passes
	}
	if s.Passes < 1 {
		s.Passes = 1
	}
	if !s.RunFile {
		s.Steps = append(s.Steps, Step{Phase: "0 Detect", Name: "invocation saved (run.json)", State: "skipped",
			Detail: "started without `args --save`: the profile comes from the ledger; flags such as --no-poc and --budget are not known, ask the user"})
	}
	add("0 Detect", "stack detected (stack.json)", exists(at("stack.json")), false, "",
		"gnark-inventory detect --repo <repo> --out "+at("stack.json"))
	add("1 Recon", "inventory and seeded ledger", exists(at("inventory.json")) && led != nil, exists(at("inventory.json")), "",
		"gnark-inventory inventory --repo <repo> --out "+out)
	if !exists(at("estimate.json")) && exists(at("bundles", "index.json")) {
		s.Steps = append(s.Steps, Step{Phase: "1 Recon", Name: "cost estimate (estimate.json)", State: "skipped", Detail: "not made; the hunt has started"})
	} else {
		add("1 Recon", "cost estimate (estimate.json)", exists(at("estimate.json")), false, "",
			"gnark-inventory estimate --out "+out+" (show it with the profile question)")
	}
	add("1 Recon", "binding table and system map", exists(at("system-map.md")) && exists(at("binding-table.md")), exists(at("binding-table.md")), "",
		"complete binding-table.md and write system-map.md (SKILL.md Phase 1)")

	// loop memory: the current pass is the first one not merged
	mem, memOK, err := memory.Load(out)
	if err != nil {
		return nil, err
	}
	memStop := false
	lastMerge := int64(0)
	if memOK {
		s.Passes = mem.PassesPlanned
		s.Pass = len(mem.Passes) + 1
		if n := len(mem.Passes); n > 0 && mem.Passes[n-1].Stop {
			memStop = true
			s.Pass = n
		}
		lastMerge = mtime(memory.Path(out))
	}

	// bundles and agents
	var rows []bundleRow
	if b, err := os.ReadFile(at("bundles", "index.json")); err == nil {
		_ = json.Unmarshal(b, &rows)
	}
	written := map[string]bool{}
	for _, r := range rows {
		if r.Status == "written" {
			written[r.Agent] = true
			s.Agents.Planned = append(s.Agents.Planned, r.Agent)
		}
	}
	add("2 Hunt", "bundles (bundles/index.json)", len(written) > 0, false, fmt.Sprintf("%d bundles", len(written)),
		"gnark-inventory bundle --out "+out+" --skill {skill} --profile "+orDefault(s.Profile))
	idx, err := agents.Load(out)
	if err != nil {
		return nil, err
	}
	byID := map[string]agents.Entry{}
	for _, e := range idx.Agents {
		byID[e.ID] = e
	}
	for _, id := range s.Agents.Planned {
		e, ok := byID[id]
		// in loop mode, an output saved before the last merge belongs to an
		// earlier pass
		if ok && memOK && !memStop && s.Pass > 1 && e.File != "" && mtime(filepath.Join(out, filepath.FromSlash(e.File))) < lastMerge {
			ok = false
		}
		switch {
		case !ok:
			s.Agents.Missing = append(s.Agents.Missing, id)
		case e.Status == "done":
			s.Agents.Done = append(s.Agents.Done, id)
		case e.Status == "blocked" || e.Attempts >= 2:
			s.Agents.Blocked = append(s.Agents.Blocked, fmt.Sprintf("%s (%s, %d attempts: %s)", id, e.Status, e.Attempts, e.Reason))
		default:
			s.Agents.Retry = append(s.Agents.Retry, fmt.Sprintf("%s (%s: %s)", id, e.Status, e.Reason))
		}
	}
	for _, e := range idx.Agents {
		if !written[e.ID] {
			s.Agents.Extra = append(s.Agents.Extra, e.ID)
		}
	}
	huntDone := len(written) > 0 && len(s.Agents.Missing) == 0 && len(s.Agents.Retry) == 0
	var act []string
	if n := len(s.Agents.Missing); n > 0 {
		act = append(act, fmt.Sprintf("spawn the %d agents with no saved output: %s", n, strings.Join(s.Agents.Missing, ", ")))
	}
	if len(s.Agents.Retry) > 0 {
		act = append(act, "retry once with plain wording: "+strings.Join(s.Agents.Retry, "; "))
	}
	if len(s.Agents.Done) > 0 {
		act = append(act, fmt.Sprintf("do not respawn the %d agents already saved", len(s.Agents.Done)))
	}
	label := "hunt"
	if s.Passes > 1 {
		label = fmt.Sprintf("hunt, pass %d of %d", s.Pass, s.Passes)
	}
	add("2 Hunt", label, huntDone, len(s.Agents.Done) > 0,
		fmt.Sprintf("%d of %d saved, %d missing, %d to retry, %d blocked", len(s.Agents.Done), len(written), len(s.Agents.Missing), len(s.Agents.Retry), len(s.Agents.Blocked)),
		strings.Join(act, "; "))

	// ledger
	cand := 0
	if led != nil {
		s.Ledger = map[string]int{}
		for _, u := range led.Units {
			s.Ledger[u.Status]++
			switch u.Status {
			case "planned", "in_progress", "candidate":
				s.Open++
			}
			if u.Status == "candidate" {
				cand++
			}
		}
	}

	// judge
	fpath := at("findings.json")
	if memOK && !memStop {
		fpath = memory.PassFindings(out, s.Pass)
	}
	var findings struct {
		Records []struct {
			Fingerprint string          `json:"fingerprint"`
			Verdict     string          `json:"verdict"`
			Layer       string          `json:"layer"`
			Severity    string          `json:"severity"`
			PoC         json.RawMessage `json:"poc"`
			Refuter     json.RawMessage `json:"refuter"`
		} `json:"records"`
	}
	fb, ferr := os.ReadFile(fpath)
	if ferr == nil {
		_ = json.Unmarshal(fb, &findings)
	}
	rel, _ := filepath.Rel(out, fpath)
	add("3 Judge", "judged records ("+filepath.ToSlash(rel)+")", ferr == nil && cand == 0, ferr == nil,
		fmt.Sprintf("%d records, %d candidate units", len(findings.Records), cand),
		"judge the saved agent outputs (judging.md), write "+filepath.ToSlash(rel)+" and close candidate units with ledger mark")

	// prove and refute
	var needPoC, needRef []string
	for _, r := range findings.Records {
		if r.Verdict != "confirmed" {
			continue
		}
		if len(r.Refuter) == 0 || string(r.Refuter) == "null" {
			needRef = append(needRef, r.Fingerprint)
		}
		if s.PoC && profOK && contains(prof.PoC.Layers, r.Layer) && contains(prof.PoC.Severities, r.Severity) && (len(r.PoC) == 0 || string(r.PoC) == "null") {
			needPoC = append(needPoC, r.Fingerprint)
		}
	}
	var pact []string
	if len(needPoC) > 0 {
		pact = append(pact, "PoC builder for "+strings.Join(needPoC, ", "))
	}
	if len(needRef) > 0 {
		pact = append(pact, "refuter for "+strings.Join(needRef, ", "))
	}
	add("4 Prove", "PoCs and refuters", ferr == nil && len(needPoC) == 0 && len(needRef) == 0, ferr == nil,
		fmt.Sprintf("%d confirmed without a PoC the policy asks for, %d without a refuter", len(needPoC), len(needRef)), strings.Join(pact, "; "))

	// critique
	if profOK && len(prof.Critics) > 0 {
		_, critic := byID["critic"]
		if !critic {
			_, critic = byID["coverage"]
		}
		check := exists(at("critic-check.json"))
		add("5 Critique", "critic check and coverage critic", critic && check, critic || check, "",
			"gnark-inventory critic-check --out "+out+", then the coverage critic (agents save --id critic), then a decision per missing unit and the targeted wave")
	} else {
		s.Steps = append(s.Steps, Step{Phase: "5 Critique", Name: "coverage critic", State: "skipped", Detail: "the profile runs no critic"})
	}
	if memOK {
		add("5 Critique", "loop memory", memStop || len(mem.Passes) >= mem.PassesPlanned, len(mem.Passes) > 0,
			fmt.Sprintf("%d of %d passes merged", len(mem.Passes), mem.PassesPlanned),
			fmt.Sprintf("gnark-inventory memory merge --out %s --pass %d --critic %s", out, s.Pass, filepath.Join(out, "passes", fmt.Sprint(s.Pass), "critic.json")))
	}

	// spend
	if l, ok, err := budget.Load(out); err == nil && ok {
		if r, err := args.Load(out); err == nil {
			l.ApplyBudget(r.BudgetUSD)
		}
		s.Spend = l.Summary()
		if l.Stopped != nil {
			s.Stopped = l.Stopped.Reason
		}
	}

	// close and report
	add("6 Report", "ledger closed", led != nil && s.Open == 0, false, fmt.Sprintf("%d units planned, in progress or candidate", s.Open),
		"ledger mark --out "+out+" --from planned --status deferred --reason \"...\" (and in_progress; judge candidates)")
	rep := at("REPORT.md")
	fresh := exists(rep) && mtime(rep) >= mtime(at("findings.json")) && mtime(rep) >= mtime(at("coverage-ledger.json"))
	s.Report = exists(rep)
	add("6 Report", "REPORT.md assembled", fresh, s.Report, map[bool]string{true: "older than findings.json or the ledger", false: ""}[s.Report && !fresh],
		"gnark-inventory validate findings ... --out "+out+", validate ledger ..., then gnark-inventory assemble --out "+out+" --repo <repo>")

	s.Complete = true
	for _, st := range s.Steps {
		if st.State == "partial" || st.State == "todo" {
			s.Complete = false
			if s.Next == "" {
				s.Next, s.NextPhase = st.Name+": "+st.Action, st.Phase
			}
		}
	}
	if s.Stopped != "" && !s.Complete {
		s.Next, s.NextPhase = "the run stopped at the budget ceiling ("+s.Stopped+"): spawn nothing; close the ledger with reason \"budget\", judge what is saved and assemble the partial report", "6 Report"
	}
	if s.Complete {
		s.Next, s.NextPhase = "nothing: the report is assembled", "done"
	}
	sort.Strings(s.Agents.Extra)
	return s, nil
}

func orDefault(p string) string {
	if p == "" {
		return profile.Load().Default().ID
	}
	return p
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Text renders the status for the orchestrator.
func (s *Status) Text() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("run %s · profile %s · passes %d · out %s\n\n", orNA(s.RunID), orNA(s.Profile), s.Passes, s.Out)
	w("| Phase | Step | State | Detail |\n|---|---|---|---|\n")
	for _, st := range s.Steps {
		w("| %s | %s | %s | %s |\n", st.Phase, st.Name, st.State, strings.ReplaceAll(st.Detail, "|", "\\|"))
	}
	if len(s.Agents.Blocked) > 0 {
		w("\nBlocked agents (record their units as blocked, do not retry): %s\n", strings.Join(s.Agents.Blocked, "; "))
	}
	if s.Spend != "" {
		w("\nSpend: %s\n", s.Spend)
	}
	w("\nNext (%s): %s\n", s.NextPhase, s.Next)
	return b.String()
}

func orNA(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
