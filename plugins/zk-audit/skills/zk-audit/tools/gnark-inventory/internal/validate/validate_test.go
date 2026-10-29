package validate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSchemasInSync keeps the embedded copies identical to the skill's
// canonical schemas ({skill}/schemas, four levels up from this package).
func TestSchemasInSync(t *testing.T) {
	n := 0
	for _, name := range Kinds {
		canon, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		emb, err := Schemas.ReadFile("schemas/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canon, emb) {
			t.Errorf("%s: embedded copy differs from plugins/zk-audit/skills/zk-audit/schemas/%s; run `make sync-schemas`", name, name)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no schemas inspected")
	}
}

const goodFindings = `{
  "schema_version": "1", "repo": "pool", "run_id": "20261027-101500", "profile": "standard",
  "records": [
    {
      "fingerprint": "TransferCircuit|res[1]|hint-output-unconstrained",
      "verdict": "confirmed", "title": "Remainder hint output is never constrained",
      "layer": "circuit", "bug_class": "hint-output-unconstrained",
      "location": {"file": "circuit/transfer.go", "line": 50, "scope": "TransferCircuit.Define"},
      "detected_by": ["C1", "V-hints"], "vector_ids": ["V-H1"],
      "description": "The prover sets the remainder to any value.",
      "severity": "high", "confidence": 90, "evidence": "POC",
      "proof": "override divHint to return remainder r-1; IsSolved still passes",
      "impact": "Accepts a false division statement.",
      "gates": {"executes": "no constraint pins res[1]", "reachable": "any prover", "unprivileged": "yes", "impact": "forged balance"},
      "fix": {"summary": "Constrain q*b + r == a and r < b."},
      "poc": {"path": "pocs/h1_test.go", "command": "go test -run PoC_H1 ./circuit", "result": "demonstrated"}
    },
    {
      "fingerprint": "Pool|withdraw|nullifier-not-bound-to-recipient",
      "verdict": "lead", "title": "Recipient may not be bound", "layer": "integration",
      "bug_class": "nullifier-not-bound-to-recipient",
      "location": {"file": "contracts/Pool.sol", "line": 40, "scope": "Pool.withdraw"},
      "detected_by": ["I1"], "description": "Recipient binding depends on circuit use of Recipient.",
      "code_smells": ["Recipient only reaches a discarded IsZero"], "unverified": "whether IsZero result is used"
    },
    {
      "fingerprint": "Verifier|verifyProof|input-not-reduced",
      "verdict": "rejected", "title": "Inputs >= r", "layer": "integration", "bug_class": "input-not-reduced",
      "location": {"file": "contracts/Verifier.sol", "line": 10, "scope": "Verifier.verifyProof"},
      "detected_by": ["I2"], "description": "Claimed inputs >= r accepted.",
      "reason": "verifier reverts with PublicInputNotInField",
      "refuting_location": {"file": "contracts/Verifier.sol", "line": 14, "scope": "Verifier.verifyProof"}
    },
    {
      "fingerprint": "deploy|vk|vk-drift",
      "verdict": "needs_validation", "title": "Deployed VK unknown", "layer": "setup", "bug_class": "vk-drift",
      "location": {"file": "cmd/setup/main.go", "line": 20, "scope": "main"},
      "detected_by": ["I2"], "description": "Cannot tell which VK is deployed.",
      "severity": "medium", "confidence": 40, "blockers": ["which VK is deployed?"],
      "validation_plan": "compare on-chain verifier bytecode with ExportSolidity output"
    }
  ]
}`

func TestFindingsValid(t *testing.T) {
	rep, err := Document("findings", []byte(goodFindings))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("expected valid, got %v", rep.Errors)
	}
	if rep.Items != 4 {
		t.Fatalf("items %d", rep.Items)
	}
}

func TestFindingsInvalid(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"poc not demonstrated": {func(s string) string {
			return strings.Replace(s, `"result": "demonstrated"`, `"result": "does_not_compile"`, 1)
		}, "evidence POC requires"},
		"missing proof": {func(s string) string {
			return strings.Replace(s, `"proof": "override divHint to return remainder r-1; IsSolved still passes",`, "", 1)
		}, "missing required property \"proof\""},
		"bad verdict":  {func(s string) string { return strings.Replace(s, `"verdict": "lead"`, `"verdict": "maybe"`, 1) }, "oneOf"},
		"bad severity": {func(s string) string { return strings.Replace(s, `"severity": "high"`, `"severity": "severe"`, 1) }, "enum"},
		"unknown field": {func(s string) string {
			return strings.Replace(s, `"severity": "high"`, `"severity": "high", "cvss": 9`, 1)
		}, "unknown property"},
		"duplicate": {func(s string) string {
			return strings.Replace(s, `Verifier|verifyProof|input-not-reduced`, `TransferCircuit|res[1]|hint-output-unconstrained`, 1)
		}, "duplicate fingerprint"},
		"no fix at 90": {func(s string) string {
			return strings.Replace(s, `"fix": {"summary": "Constrain q*b + r == a and r < b."},`, "", 1)
		}, "requires a fix"},
		"bad fingerprint": {func(s string) string { return strings.Replace(s, `deploy|vk|vk-drift`, `no pipes here`, 1) }, "does not match"},
	}
	for name, c := range cases {
		rep, err := Document("findings", []byte(c.mutate(goodFindings)))
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK() || !strings.Contains(strings.Join(rep.Errors, "\n"), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, rep.Errors)
		}
	}
}

func TestZeroItemsFail(t *testing.T) {
	empty := `{"schema_version":"1","repo":"r","run_id":"20261027-101500","profile":"quick","records":[]}`
	rep, _ := Document("findings", []byte(empty))
	if rep.OK() {
		t.Fatal("empty findings without no_findings must fail")
	}
	explicit := `{"schema_version":"1","repo":"r","run_id":"20261027-101500","profile":"quick","no_findings":true,"no_findings_reason":"all 12 ledger units covered; no candidate survived judging","records":[]}`
	rep, _ = Document("findings", []byte(explicit))
	if !rep.OK() {
		t.Fatalf("explicit no-findings should pass: %v", rep.Errors)
	}
	ledger := `{"schema_version":"1","repo":"r","generated_by":"t","units":[]}`
	rep, _ = Document("ledger", []byte(ledger))
	if rep.OK() {
		t.Fatal("empty ledger must fail")
	}
}

func TestLedger(t *testing.T) {
	good := `{"schema_version":"1","repo":"r","generated_by":"t","units":[
	 {"id":"circuit:TransferCircuit|hint-soundness","kind":"circuit","subject":"TransferCircuit","class":"hint-soundness","lenses":["C1"],"paths":["circuit/transfer.go:40"],"status":"covered","agent_ids":["C1"],"reviewed_paths":["circuit/transfer.go"],"result_fingerprints":[]},
	 {"id":"contract-fn:Pool.withdraw|protocol-state","kind":"contract-fn","subject":"Pool.withdraw","class":"protocol-state","lenses":["I3"],"paths":["contracts/Pool.sol:30"],"status":"deferred","agent_ids":[],"reviewed_paths":[],"result_fingerprints":[],"reason":"quick profile"}
	]}`
	rep, err := Document("ledger", []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("expected valid ledger: %v", rep.Errors)
	}
	bad := strings.Replace(good, `"reason":"quick profile"`, `"reason":""`, 1)
	bad = strings.Replace(bad, `"agent_ids":["C1"]`, `"agent_ids":[]`, 1)
	bad = strings.Replace(bad, `"id":"contract-fn:Pool.withdraw|protocol-state"`, `"id":"contract-fn:Pool.withdraw|hint-soundness"`, 1)
	rep, _ = Document("ledger", []byte(bad))
	joined := strings.Join(rep.Errors, "\n")
	for _, want := range []string{"needs a reason", "covered units need", "must end with its class"} {
		if !strings.Contains(joined, want) {
			t.Errorf("want %q in %s", want, joined)
		}
	}
}
