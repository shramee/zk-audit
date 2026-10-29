package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skill is the skill folder that holds this tool:
// profile -> internal -> gnark-inventory -> tools -> zk-audit.
var skill = filepath.Join("..", "..", "..", "..")

func TestEmbeddedProfiles(t *testing.T) {
	s := Load()
	if len(s.Lenses) < 20 || len(s.Profiles) != 3 {
		t.Fatalf("%d lenses, %d profiles", len(s.Lenses), len(s.Profiles))
	}
	if s.Default().ID != "standard" {
		t.Errorf("default profile %s", s.Default().ID)
	}
	for _, m := range s.CheckFiles(skill) {
		t.Error(m)
	}
	// every quick lens is in standard, every standard lens is in deep
	for _, l := range s.Lenses {
		if l.In("quick") && !l.In("standard") || l.In("standard") && !l.In("deep") {
			t.Errorf("lens %s: profiles %v are not nested quick ⊂ standard ⊂ deep", l.ID, l.Profiles)
		}
	}
	if p, _ := s.Profile("deep"); p.Passes < 2 || !p.Memory {
		t.Errorf("deep: %+v", p)
	}
}

// TestEveryLensFileIsUsed fails when a lens file exists under
// references/agents/ that no profiles.json entry names: a lens added without
// its definition would never run.
func TestEveryLensFileIsUsed(t *testing.T) {
	used := map[string]bool{}
	for _, l := range Load().Lenses {
		used[l.File] = true
	}
	files, _ := filepath.Glob(filepath.Join(skill, "references", "agents", "*.md"))
	if len(files) == 0 {
		t.Fatal("no lens files found")
	}
	for _, f := range files {
		if rel := "agents/" + filepath.Base(f); !used[rel] {
			t.Errorf("references/%s is not named by any lens in profiles.json", rel)
		}
	}
}

// TestGeneratedDocsInSync keeps the profile table in SKILL.md and the agent
// table in references/orchestration.md identical to profiles.json. Run
// `make sync-profiles` after editing profiles.json.
func TestGeneratedDocsInSync(t *testing.T) {
	drift, err := Load().SyncDocs(skill, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range drift {
		t.Errorf("%s differs from profiles.json; run `make sync-profiles`", d)
	}
}

func TestSyncDocsRewrites(t *testing.T) {
	dir := t.TempDir()
	for _, r := range Regions {
		p := filepath.Join(dir, filepath.FromSlash(r.File))
		os.MkdirAll(filepath.Dir(p), 0o755)
		doc := "intro\n<!-- generated:" + r.Name + " from profiles.json (make sync-profiles); do not edit -->\nstale\n<!-- end generated:" + r.Name + " -->\noutro\n"
		os.WriteFile(p, []byte(doc), 0o644)
	}
	s := Load()
	drift, err := s.SyncDocs(dir, true)
	if err != nil || len(drift) != len(Regions) {
		t.Fatalf("drift %v err %v", drift, err)
	}
	if drift, _ := s.SyncDocs(dir, false); len(drift) != 0 {
		t.Fatalf("still drifting after a rewrite: %v", drift)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if !strings.Contains(string(b), "| `standard` (default) |") || strings.Contains(string(b), "stale") || !strings.HasSuffix(string(b), "outro\n") {
		t.Errorf("rewritten doc:\n%s", b)
	}
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("no markers"), 0o644)
	if _, err := s.SyncDocs(dir, false); err == nil {
		t.Error("missing markers must be an error")
	}
}

func TestParseRejects(t *testing.T) {
	base := `{"schema_version":"1","critics":[{"id":"coverage","name":"c","agent":"critic"}],
"profiles":[{"id":"quick","default":true,"poc":{"layers":["circuit"],"severities":["high"],"text":"x"},"refuters":{"verdicts":["confirmed"],"text":"one"},"critics":[],"passes":1}],
"lenses":[%s]}`
	cases := map[string]string{
		"duplicate id":   `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"]},{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"]}`,
		"unknown shard":  `{"id":"C1","name":"a","file":"f","group":"g","shard":"nowhere","profiles":["quick"]}`,
		"unknown prof":   `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["huge"]}`,
		"no profile":     `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":[]}`,
		"class twice":    `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"ledger":{"classes":["x"]}},{"id":"C2","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"ledger":{"classes":["x"]}}`,
		"bad seed":       `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"ledger":{"classes":["x"],"seed":"galaxy"}}`,
		"unknown with":   `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"ledger":{"classes":["x"],"with":["Z9"]}}`,
		"unknown field":  `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"colour":"red"}`,
		"lowercase id":   `{"id":"c1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"]}`,
		"missing fields": `{"id":"C1","shard":"circuit","profiles":["quick"]}`,
		"unknown when":   `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"when":"full-moon"}`,
	}
	ok := `{"id":"C1","name":"a","file":"f","group":"g","shard":"circuit","profiles":["quick"],"ledger":{"classes":["x"],"seed":"circuit","with":["V"]}}`
	if _, err := Parse([]byte(strings.Replace(base, "%s", ok, 1))); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	for name, lenses := range cases {
		if _, err := Parse([]byte(strings.Replace(base, "%s", lenses, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	badStep := strings.Replace(strings.Replace(base, "%s", ok, 1), `"passes":1}`, `"passes":1,"provenance":["abi","telepathy"]}`, 1)
	if _, err := Parse([]byte(badStep)); err == nil || !strings.Contains(err.Error(), "telepathy") {
		t.Errorf("unknown provenance step: %v", err)
	}
}

// TestProvenanceSteps: every profile runs the static ABI check and the
// ceremony scan; only deep regenerates the verifier in the sandbox.
func TestProvenanceSteps(t *testing.T) {
	for _, p := range Load().Profiles {
		got := strings.Join(p.Provenance, ",")
		want := "abi,ceremony"
		if p.ID == "deep" {
			want = "abi,ceremony,regen"
		}
		if got != want {
			t.Errorf("profile %s: provenance %s, want %s", p.ID, got, want)
		}
	}
}

func TestAgentKnown(t *testing.T) {
	s := Load()
	for _, id := range []string{"C1", "C1@circuit/vote", "V-hints", "G2", "critic", "coverage"} {
		if !s.AgentKnown(id) {
			t.Errorf("%s should be known", id)
		}
	}
	for _, id := range []string{"Z1", "c1", "", "@x"} {
		if s.AgentKnown(id) {
			t.Errorf("%s should be unknown", id)
		}
	}
}
