package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/agents"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/args"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/budget"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

const ledgerJSON = `{"schema_version":"1","repo":"/r","run_id":"20261029-100000","profile":"standard","generated_by":"test","units":[
{"id":"circuit:A|hint-soundness","kind":"circuit","subject":"A","class":"hint-soundness","lenses":["C1"],"paths":["a.go:1"],"status":"%s","agent_ids":[],"reviewed_paths":[],"result_fingerprints":[],"wave":0}]}`

func TestResumeFromAnInterruptedHunt(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()
	run, err := args.Parse([]string{"standard", "--budget", "50"}, args.Options{Repo: repo, Home: home, Now: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if err := args.Save(run); err != nil {
		t.Fatal(err)
	}
	out := run.Out
	for _, f := range []string{"stack.json", "inventory.json", "estimate.json", "binding-table.md", "system-map.md"} {
		write(t, filepath.Join(out, f), "{}")
	}
	write(t, filepath.Join(out, "coverage-ledger.json"), strings.Replace(ledgerJSON, "%s", "planned", 1))
	write(t, filepath.Join(out, "bundles", "index.json"), `[{"agent":"C1","status":"written"},{"agent":"I1","status":"written"},{"agent":"G2","status":"written"},{"agent":"L1","status":"skipped","reason":"not in profile"}]`)
	agents.Save(out, "C1", "FINDING | x\n", "done", "")
	agents.Save(out, "I1", "", "refused", "safety classifier")
	l, _, _ := budget.Load(out)
	l.Profile = "standard"
	l.Record(budget.Entry{ID: "C1", Tokens: 50000})
	l.Save(out)

	s, err := Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if !s.RunFile || s.Profile != "standard" || s.RunID != run.RunID || s.Complete {
		t.Errorf("header: %+v", s)
	}
	if strings.Join(s.Agents.Done, ",") != "C1" || strings.Join(s.Agents.Missing, ",") != "G2" || len(s.Agents.Retry) != 1 || !strings.HasPrefix(s.Agents.Retry[0], "I1") {
		t.Errorf("agents: %+v", s.Agents)
	}
	if s.NextPhase != "2 Hunt" || !strings.Contains(s.Next, "G2") || !strings.Contains(s.Next, "retry once") || !strings.Contains(s.Next, "do not respawn the 1") {
		t.Errorf("next: %s (%s)", s.Next, s.NextPhase)
	}
	if !strings.Contains(s.Spend, "budget 50.00 USD") {
		t.Errorf("spend: %s", s.Spend)
	}
	// a second refusal blocks I1; G2 is saved: the hunt is done, judging is next
	agents.Save(out, "I1", "", "refused", "safety classifier, retried once")
	agents.Save(out, "G2", "no findings: read a.go\n", "done", "")
	s, _ = Read(out)
	if len(s.Agents.Blocked) != 1 || s.NextPhase != "3 Judge" {
		t.Errorf("after the retry: %+v next %s", s.Agents, s.NextPhase)
	}
	if txt := s.Text(); !strings.Contains(txt, "Blocked agents") || !strings.Contains(txt, "| 2 Hunt | hunt | done |") {
		t.Errorf("text:\n%s", txt)
	}
	// judged, proved, criticised, closed and assembled
	write(t, filepath.Join(out, "findings.json"), `{"records":[{"fingerprint":"a","verdict":"confirmed","layer":"circuit","severity":"high","poc":{"result":"demonstrated"},"refuter":{"verdict":"exploitable"}}]}`)
	write(t, filepath.Join(out, "coverage-ledger.json"), strings.Replace(ledgerJSON, "%s", "covered", 1))
	agents.Save(out, "critic", "{\"missing_units\": []}\n", "done", "")
	write(t, filepath.Join(out, "critic-check.json"), `{}`)
	time.Sleep(10 * time.Millisecond)
	write(t, filepath.Join(out, "REPORT.md"), "# r\n")
	s, _ = Read(out)
	if !s.Complete || s.NextPhase != "done" {
		t.Errorf("complete run: %+v\n%s", s, s.Text())
	}
	// a budget stop sends the run to the report
	l, _, _ = budget.Load(out)
	l.BudgetUSD = 1
	l.Check("targeted wave", budget.Wave{"wave": 1}, 0)
	l.Save(out)
	os.Remove(filepath.Join(out, "REPORT.md"))
	s, _ = Read(out)
	if s.Stopped == "" || !strings.Contains(s.Next, "budget ceiling") {
		t.Errorf("budget stop: %s / %s", s.Stopped, s.Next)
	}
}
