package args

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSplit(t *testing.T) {
	cases := map[string][]string{
		`quick a.go --loop 2`:            {"quick", "a.go", "--loop", "2"},
		`  "my dir/x.go"  'b c.sol' `:    {"my dir/x.go", "b c.sol"},
		`--out=~/x\ y`:                   {"--out=~/x y"},
		`a"b"c 'it''s'`:                  {"abc", "its"},
		`"esc \" quote"`:                 {`esc " quote`},
		``:                               nil,
		"diff\torigin/main..HEAD\n":      {"diff", "origin/main..HEAD"},
		`--file-output --no-poc deep`:    {"--file-output", "--no-poc", "deep"},
		`recon circuits/ contracts/`:     {"recon", "circuits/", "contracts/"},
		`"" x`:                           {"", "x"},
		`--loop=3 --profile standard`:    {"--loop=3", "--profile", "standard"},
		`a\\b`:                           {`a\b`},
		`'$HOME' "$(rm -rf /)"`:          {"$HOME", "$(rm -rf /)"},
		`one two  three`:                 {"one", "two", "three"},
		`--out /tmp/z --local`:           {"--out", "/tmp/z", "--local"},
		`circuits/vote.go,x.go`:          {"circuits/vote.go,x.go"},
		`quick --local --loop 1 --out=o`: {"quick", "--local", "--loop", "1", "--out=o"},
	}
	for in, want := range cases {
		got, err := Split(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Split(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{`"open`, `'open`, `trailing\`} {
		if _, err := Split(in); err == nil {
			t.Errorf("Split(%q): want an error", in)
		}
	}
}

func repo(t *testing.T) string {
	t.Helper()
	r := filepath.Join(t.TempDir(), "my-repo")
	for _, f := range []string{"circuits/vote.go", "contracts/Ballot.sol", "go.mod"} {
		p := filepath.Join(r, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("x\n"), 0o644)
	}
	return r
}

func parse(t *testing.T, r, in string, opt Options) (*Run, error) {
	t.Helper()
	w, err := Split(in)
	if err != nil {
		t.Fatal(err)
	}
	opt.Repo = r
	if opt.Home == "" {
		opt.Home = "/home/u"
	}
	if opt.Now.IsZero() {
		opt.Now = time.Date(2026, 10, 29, 9, 8, 7, 0, time.UTC)
	}
	return Parse(w, opt)
}

func TestDefaults(t *testing.T) {
	r := repo(t)
	run, err := parse(t, r, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Mode != "audit" || run.Profile != "standard" || run.ProfileExplicit || run.Passes != 1 || run.Memory || !run.PoC || run.Local || run.FileOutput {
		t.Errorf("defaults: %+v", run)
	}
	if run.RunID != "20261029-090807" || run.Out != "/home/u/.zk-audit/my-repo/20261029-090807" || run.RepoName != "my-repo" {
		t.Errorf("out: %s %s %s", run.RunID, run.Out, run.RepoName)
	}
	if len(run.Scope) != 0 || run.Diff != nil || run.ReportCopy != "" {
		t.Errorf("scope/diff: %+v", run)
	}
}

func TestFullInvocation(t *testing.T) {
	r := repo(t)
	run, err := parse(t, r, `deep circuits/vote.go ./contracts/Ballot.sol --local --loop 4 --no-poc --file-output --out /tmp/zk-out`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Profile != "deep" || !run.ProfileExplicit || !run.Local || run.Passes != 4 || !run.Memory || !run.LoopExplicit || run.PoC || !run.FileOutput {
		t.Errorf("flags: %+v", run)
	}
	if !reflect.DeepEqual(run.Scope, []string{"circuits/vote.go", "contracts/Ballot.sol"}) {
		t.Errorf("scope %q", run.Scope)
	}
	if run.Out != "/tmp/zk-out" || !run.OutExplicit {
		t.Errorf("out %s", run.Out)
	}
	if want := filepath.Join(run.Repo, "zk-audit-report-20261029-090807.md"); run.ReportCopy != want {
		t.Errorf("report copy %s, want %s", run.ReportCopy, want)
	}
	if len(run.Warnings) == 0 {
		t.Error("--local with --loop should warn")
	}
}

func TestProfileDefaultsPasses(t *testing.T) {
	r := repo(t)
	run, err := parse(t, r, "deep", Options{})
	if err != nil || run.Passes != 3 || !run.Memory || run.LoopExplicit {
		t.Fatalf("deep: %+v %v", run, err)
	}
	run, err = parse(t, r, "--profile=quick --loop=1", Options{})
	if err != nil || run.Profile != "quick" || run.Passes != 1 || run.Memory {
		t.Fatalf("quick: %+v %v", run, err)
	}
	run, err = parse(t, r, "--loop 2", Options{})
	if err != nil || run.Profile != "standard" || run.Passes != 2 || !run.Memory {
		t.Fatalf("standard loop: %+v %v", run, err)
	}
}

func TestModes(t *testing.T) {
	r := repo(t)
	run, err := parse(t, r, "diff", Options{})
	if err != nil || run.Mode != "diff" || run.Diff.Base != "origin/main" || run.Diff.Head != "HEAD" {
		t.Fatalf("diff default: %+v %v", run, err)
	}
	run, err = parse(t, r, "diff v1.2.0..feature/x circuits/", Options{})
	if err != nil || run.Diff.Base != "v1.2.0" || run.Diff.Head != "feature/x" || !reflect.DeepEqual(run.Scope, []string{"circuits"}) {
		t.Fatalf("diff range: %+v %v", run, err)
	}
	run, err = parse(t, r, "main...HEAD~2", Options{Mode: "diff"})
	if err != nil || run.Diff.Base != "main" || run.Diff.Head != "HEAD~2" {
		t.Fatalf("forced diff: %+v %v", run, err)
	}
	run, err = parse(t, r, "diff circuits/vote.go", Options{})
	if err != nil || run.Diff.Base != "origin/main" || len(run.Scope) != 1 {
		t.Fatalf("diff with only a path: %+v %v", run, err)
	}
	run, err = parse(t, r, "recon quick circuits", Options{})
	if err != nil || run.Mode != "recon" || len(run.Warnings) == 0 {
		t.Fatalf("recon: %+v %v", run, err)
	}
	run, err = parse(t, r, "--check-only", Options{Mode: "setup"})
	if err != nil || run.Mode != "setup" || !run.CheckOnly {
		t.Fatalf("setup: %+v %v", run, err)
	}
}

func TestInvalid(t *testing.T) {
	r := repo(t)
	cases := map[string]string{
		"--bogus":                   "unknown flag",
		"--loop":                    "--loop needs a value",
		"--loop 0":                  "from 1 to",
		"--loop 99":                 "from 1 to",
		"--loop two":                "from 1 to",
		"--profile huge":            "unknown profile",
		"quick deep":                "two profiles",
		"missing.go":                "does not exist",
		"../outside":                "does not exist",
		"recon --loop 2":            "--loop applies to a full audit",
		"setup circuits":            "setup mode takes no scope",
		"quick --check-only":        "setup mode only",
		"--out " + r + "/audit-out": "inside the target repository",
		"--out":                     "--out needs a value",
		"diff --bogus":              "unknown flag",
		"diff main..-x":             "is not a revision",
	}
	for in, want := range cases {
		_, err := parse(t, r, in, Options{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", in, err, want)
		}
	}
	if _, err := parse(t, r, "", Options{RunID: "yesterday"}); err == nil {
		t.Error("bad run id accepted")
	}
	if _, err := parse(t, r, "", Options{Mode: "explode"}); err == nil {
		t.Error("bad mode accepted")
	}
}

func TestScopeSymlinkEscape(t *testing.T) {
	r := repo(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.go"), []byte("x"), 0o644)
	if err := os.Symlink(filepath.Join(outside, "secret.go"), filepath.Join(r, "link.go")); err != nil {
		t.Skip(err)
	}
	if _, err := parse(t, r, "link.go", Options{}); err == nil || !strings.Contains(err.Error(), "outside the repository") {
		t.Errorf("symlink out of the repo accepted: %v", err)
	}
	// an --out that reaches the repo through a symlink is still inside it
	alias := filepath.Join(t.TempDir(), "alias")
	os.Symlink(r, alias)
	if _, err := parse(t, r, "--out "+alias+"/o", Options{}); err == nil {
		t.Error("--out through a symlink into the repo accepted")
	}
}

func TestBudget(t *testing.T) {
	r := repo(t)
	home := t.TempDir()
	run, err := parse(t, r, "standard --budget 30", Options{Home: home})
	if err != nil || run.BudgetUSD != 30 {
		t.Fatalf("--budget 30: %v %+v", err, run)
	}
	if run, err = parse(t, r, "--budget=$12.5", Options{Home: home}); err != nil || run.BudgetUSD != 12.5 {
		t.Errorf("--budget=$12.5: %v %v", err, run)
	}
	for _, in := range []string{"--budget 0", "--budget -3", "--budget lots", "recon --budget 5", "--budget"} {
		if _, err := parse(t, r, in, Options{Home: home}); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
}

func TestSaveAndResume(t *testing.T) {
	r := repo(t)
	home := t.TempDir()
	at := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	run, err := parse(t, r, "deep circuits/vote.go --budget 40 --no-poc", Options{Home: home, Now: at})
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(run); err != nil {
		t.Fatal(err)
	}
	// a second run with the same output directory is refused
	again, _ := parse(t, r, "quick", Options{Home: home, Now: at})
	if err := Save(again); err == nil || !strings.Contains(err.Error(), "resume") {
		t.Errorf("overwriting another run's run.json: %v", err)
	}
	// resume by id, by directory, and the latest unfinished run
	for _, in := range []string{"resume 20261029-100000", "resume " + run.Out, "resume"} {
		got, err := parse(t, r, in, Options{Home: home})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if !got.Resume || got.Mode != "audit" || got.Profile != "deep" || got.PoC || got.BudgetUSD != 40 ||
			got.Out != run.Out || got.RunID != run.RunID || !reflect.DeepEqual(got.Scope, []string{"circuits/vote.go"}) {
			t.Errorf("%q: %+v", in, got)
		}
	}
	got, err := parse(t, r, "resume --budget 60", Options{Home: home})
	if err != nil || got.BudgetUSD != 60 {
		t.Errorf("resume --budget 60: %v %+v", err, got)
	}
	if err := Save(got); err != nil {
		t.Errorf("saving a resumed run: %v", err)
	}
	// a finished run (REPORT.md) is not picked by a bare resume
	os.WriteFile(filepath.Join(run.Out, "REPORT.md"), []byte("x"), 0o644)
	if _, err := parse(t, r, "resume", Options{Home: home}); err == nil {
		t.Error("bare resume picked a finished run")
	}
	for _, in := range []string{"resume nope", "resume 20200101-000000", "resume a b", "resume --loop 2"} {
		if _, err := parse(t, r, in, Options{Home: home}); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
	// a run of another repository
	other := repo(t)
	if _, err := parse(t, other, "resume "+run.Out, Options{Home: home}); err == nil {
		t.Error("resumed a run of another repository")
	}
}
