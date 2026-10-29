package threatmodel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const filled = `# zk-audit threat model

<!-- notes -->

## Scope

- circuits/
- ` + "`contracts/Ballot.sol`" + `

## Out of scope

| Path or area | Reason |
|---|---|
| contracts/mocks/ | test helpers |

## Trusted parties

| Party | Trust | Powers | Notes |
|---|---|---|---|
| owner | trusted | replaces the verifier | multisig |
| tallier | bounded | posts the tally root | only after the election closes |
| relayer | untrusted | submits proofs | anyone |

## Properties

| Id | Property |
|---|---|
| PROP-1 | A ballot is counted at most once. |

## Accepted risks

| Id | Party | Risk | Notes |
|---|---|---|---|
| AR-1 | owner | can replace the verifier | governance |

## Prior findings

| Id | Fingerprint | Status | Title |
|---|---|---|---|
| PF-1 | ` + "`BallotCircuit\\|tally\\|hint-unbound`" + ` | fixed | Tally hint unbound |

## Deployment

| Fact | Value |
|---|---|
| chain ids | 1, 10 |

## Glossary

Words.
`

func TestParseFilled(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "circuits"), 0o755)
	d, err := Parse([]byte(filled), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Scope.In) != 2 || d.Scope.In[1].Path != "contracts/Ballot.sol" || d.Scope.In[0].Line != 7 {
		t.Errorf("scope: %+v", d.Scope.In)
	}
	if len(d.Scope.Out) != 1 || d.Scope.Out[0].Reason != "test helpers" {
		t.Errorf("out: %+v", d.Scope.Out)
	}
	if len(d.TrustedParties) != 3 || d.TrustedParties[1].Trust != "bounded" || d.TrustedParties[0].Line != 20 {
		t.Errorf("parties: %+v", d.TrustedParties)
	}
	if len(d.AcceptedRisks) != 1 || d.AcceptedRisks[0].Line != 34 {
		t.Errorf("risks: %+v", d.AcceptedRisks)
	}
	if len(d.PriorFindings) != 1 || d.PriorFindings[0].Fingerprint != "BallotCircuit|tally|hint-unbound" {
		t.Errorf("prior: %+v", d.PriorFindings)
	}
	if len(d.Properties) != 1 || len(d.Deployment) != 1 {
		t.Errorf("properties %+v deployment %+v", d.Properties, d.Deployment)
	}
	w := strings.Join(d.Warnings, "\n")
	if !strings.Contains(w, `"Glossary"`) || !strings.Contains(w, "contracts/Ballot.sol\" does not exist") {
		t.Errorf("warnings: %s", w)
	}
	if what, ok := d.AcceptsLine(34); !ok || what != "accepted risk AR-1" {
		t.Errorf("line 34: %s %v", what, ok)
	}
	if _, ok := d.AcceptsLine(20); !ok {
		t.Error("a trusted party's line accepts its powers")
	}
	if _, ok := d.AcceptsLine(21); ok {
		t.Error("a bounded party's line accepts nothing")
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"trust level":    "## Trusted parties\n\n| Party | Trust |\n|---|---|\n| owner | mostly |\n",
		"missing column": "## Accepted risks\n\n| Id | Risk |\n|---|---|\n| AR-1 | x |\n",
		"bad id":         "## Properties\n\n| Id | Property |\n|---|---|\n| one | x |\n",
		"duplicate id":   "## Properties\n\n| Id | Property |\n|---|---|\n| P-1 | x |\n| P-1 | y |\n",
		"fingerprint":    "## Prior findings\n\n| Id | Fingerprint | Status |\n|---|---|---|\n| PF-1 | just words | fixed |\n",
		"prior status":   "## Prior findings\n\n| Id | Fingerprint | Status |\n|---|---|---|\n| PF-1 | a\\|b\\|c | done |\n",
		"untrusted risk": "## Trusted parties\n\n| Party | Trust |\n|---|---|\n| relayer | untrusted |\n\n## Accepted risks\n\n| Id | Party | Risk |\n|---|---|---|\n| AR-1 | relayer | front-runs |\n",
		"scope escape":   "## Scope\n\n- ../other\n",
		"no separator":   "## Properties\n\n| Id | Property |\n| P-1 | x |\n",
		"twice":          "## Scope\n\n- a\n\n## Scope\n\n- b\n",
	} {
		if _, err := Parse([]byte(in), ""); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The shipped template parses, and every one of its rows is a placeholder.
func TestTemplateParses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "templates", FileName))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(b, "")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if n := len(d.TrustedParties) + len(d.AcceptedRisks) + len(d.Properties) + len(d.PriorFindings) + len(d.Deployment) + len(d.Scope.In) + len(d.Scope.Out); n != 0 {
		t.Errorf("template rows parsed as entries: %d", n)
	}
	if !strings.Contains(strings.Join(d.Warnings, "\n"), "empty template") {
		t.Errorf("warnings: %v", d.Warnings)
	}
	// filled in: strip the angle brackets of every placeholder
	f := strings.NewReplacer("<", "", ">", "").Replace(string(b))
	f = strings.Replace(f, "!--", "<!--", 1)
	f = strings.Replace(f, "--\n\n## Scope", "-->\n\n## Scope", 1)
	d, err = Parse([]byte(f), "")
	if err != nil {
		t.Fatalf("filled template: %v", err)
	}
	if len(d.TrustedParties) != 2 || len(d.AcceptedRisks) != 1 || len(d.PriorFindings) != 1 || len(d.Deployment) != 5 || len(d.Scope.In) != 2 {
		t.Errorf("filled template: %+v", d)
	}
}
