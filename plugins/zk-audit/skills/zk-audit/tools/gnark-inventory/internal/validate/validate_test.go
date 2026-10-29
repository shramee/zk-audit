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

// TestLedgerLensesAndClassesFromProfiles checks that ledger classes and
// lenses are validated against profiles.json, not a schema enum.
func TestLedgerLensesAndClassesFromProfiles(t *testing.T) {
	doc := `{"schema_version":"1","repo":"r","generated_by":"t","units":[
	 {"id":"circuit:C|made-up-class","kind":"circuit","subject":"C","class":"made-up-class","lenses":["Z9","V"],"paths":["c.go:1"],"status":"planned","agent_ids":[],"reviewed_paths":[],"result_fingerprints":[]}
	]}`
	rep, err := Document("ledger", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Errors, "\n")
	for _, want := range []string{`class "made-up-class" is owned by no lens`, `lens "Z9" is not defined`} {
		if !strings.Contains(joined, want) {
			t.Errorf("want %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, `lens "V"`) {
		t.Errorf("V (the vector scan) must be accepted: %s", joined)
	}
}

func pocDoc(evidence, result, path, extra string) string {
	return `{"schema_version":"1","repo":"r","run_id":"20261029-101010","profile":"standard","records":[
	{"fingerprint":"VoteCircuit|tally|hint-output-unconstrained","verdict":"confirmed","calibration":"SC-UNUSED-FREE-VALUE","title":"t","layer":"circuit","bug_class":"hint-output-unconstrained",
	 "location":{"file":"c/vote.go","line":3,"scope":"VoteCircuit.Define"},"detected_by":["C1"],"description":"d",
	 "severity":"low","confidence":60,"evidence":"` + evidence + `","proof":"p","impact":"i",
	 "gates":{"executes":"e","reachable":"r","unprivileged":"u","impact":"i"},
	 "poc":{"path":"` + path + `","command":"go test","result":"` + result + `"` + extra + `}},
	{"fingerprint":"VoteCircuit|owner|owner-gate","verdict":"lead","title":"t2","layer":"circuit","bug_class":"owner-gate",
	 "location":{"file":"c/vote.go","line":5,"scope":"VoteCircuit.Define"},"detected_by":["C4"],"description":"d",
	 "code_smells":["s"],"unverified":"u","poc":{"path":"pocs/2_poc_test.go","command":"go test","result":"demonstrated","demonstrates":"soundness"}}
	]}`
}

// TestPoCTruthfulness: with --out, a PoC must exist under <out>/pocs/;
// model-only PoCs keep ANALYSIS; orphan PoC files and a missing
// `demonstrates` are warnings; a demoted record may keep its PoC.
func TestPoCTruthfulness(t *testing.T) {
	out := t.TempDir()
	os.MkdirAll(filepath.Join(out, "pocs"), 0o755)
	os.WriteFile(filepath.Join(out, "pocs", "1_poc_test.go"), []byte("package c"), 0o644)
	os.WriteFile(filepath.Join(out, "pocs", "2_poc_test.go"), []byte("package c"), 0o644)
	run := func(doc string, o Options) *Report {
		t.Helper()
		rep, err := DocumentWith("findings", []byte(doc), o)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	has := func(xs []string, sub string) bool { return strings.Contains(strings.Join(xs, "\n"), sub) }
	ok := run(pocDoc("POC", "demonstrated", "pocs/1_poc_test.go", `,"demonstrates":"soundness"`), Options{Out: out})
	if !ok.OK() || len(ok.Warnings) != 0 {
		t.Fatalf("valid PoC: %v %v", ok.Errors, ok.Warnings)
	}
	cases := []struct {
		name, doc     string
		errs, warning string
	}{
		{"missing file", pocDoc("POC", "demonstrated", "pocs/9_poc_test.go", `,"demonstrates":"soundness"`), "does not exist under", ""},
		{"escapes pocs", pocDoc("POC", "demonstrated", "../etc/passwd", `,"demonstrates":"soundness"`), "is not under <out>/pocs/", ""},
		{"model only behind POC", pocDoc("POC", "demonstrated_on_model", "pocs/1_poc_test.go", `,"demonstrates":"soundness"`), "keeps evidence ANALYSIS", ""},
		{"not demonstrated behind POC", pocDoc("POC", "not_demonstrated", "pocs/1_poc_test.go", ``), "requires poc.result", ""},
		{"no demonstrates", pocDoc("POC", "demonstrated", "pocs/1_poc_test.go", ``), "", "poc.demonstrates is missing"},
		{"orphan", strings.Replace(pocDoc("ANALYSIS", "demonstrated_on_model", "pocs/1_poc_test.go", `,"demonstrates":"soundness"`), "pocs/2_poc_test.go", "pocs/1_poc_test.go", 1), "", "pocs/2_poc_test.go is not the poc.path of any record"},
		{"not run, no file", pocDoc("ANALYSIS", "not_run", "pocs/7_poc_test.go", ``), "", "does not exist under"},
	}
	for _, c := range cases {
		rep := run(c.doc, Options{Out: out})
		if c.errs != "" && !has(rep.Errors, c.errs) {
			t.Errorf("%s: want error %q, got %v", c.name, c.errs, rep.Errors)
		}
		if c.errs == "" && !rep.OK() {
			t.Errorf("%s: unexpected errors %v", c.name, rep.Errors)
		}
		if c.warning != "" && !has(rep.Warnings, c.warning) {
			t.Errorf("%s: want warning %q, got %v", c.name, c.warning, rep.Warnings)
		}
	}
	// without --out the files are not checked
	if rep := run(pocDoc("POC", "demonstrated", "pocs/9_poc_test.go", `,"demonstrates":"soundness"`), Options{}); !rep.OK() {
		t.Errorf("no --out: %v", rep.Errors)
	}
}

// TestLedgerTruthfulness: covered units need saved agent outputs (with
// --out) and reviewed_paths that include the unit's own file.
func TestLedgerTruthfulness(t *testing.T) {
	out := t.TempDir()
	os.MkdirAll(filepath.Join(out, "agents"), 0o755)
	os.WriteFile(filepath.Join(out, "agents", "C1.md"), []byte("FINDING ..."), 0o644)
	os.WriteFile(filepath.Join(out, "agents", "C2__circuit_vote.md"), []byte("no findings: read vote.go"), 0o644)
	unit := func(agents, reviewed string) string {
		return `{"schema_version":"1","repo":"r","generated_by":"t","units":[
		{"id":"circuit:VoteCircuit|hint-soundness","kind":"circuit","subject":"VoteCircuit","class":"hint-soundness","lenses":["C1"],"paths":["circuit/vote.go:40"],"status":"covered","agent_ids":` + agents + `,"reviewed_paths":` + reviewed + `,"result_fingerprints":[]}]}`
	}
	cases := []struct {
		name, doc, err, warn string
	}{
		{"ok", unit(`["C1","C2@circuit/vote"]`, `["circuit/vote.go","circuit/hints.go"]`), "", ""},
		{"dir counts", unit(`["C1"]`, `["circuit/"]`), "", ""},
		{"no output", unit(`["C1","C3"]`, `["circuit/vote.go"]`), "agent C3 has no saved output", ""},
		{"other file", unit(`["C1"]`, `["circuit/other.go"]`), "do not include the unit's own file", ""},
		{"absolute", unit(`["C1"]`, `["/etc/passwd","circuit/vote.go"]`), "not a repository-relative path", ""},
		{"unknown agent", unit(`["C1","W1"]`, `["circuit/vote.go"]`), "agent W1 has no saved output", "agent id W1 is no lens"},
	}
	for _, c := range cases {
		rep, err := DocumentWith("ledger", []byte(c.doc), Options{Out: out})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(rep.Errors, "\n")
		if c.err == "" && !rep.OK() || c.err != "" && !strings.Contains(joined, c.err) {
			t.Errorf("%s: errors %v, want %q", c.name, rep.Errors, c.err)
		}
		if c.warn != "" && !strings.Contains(strings.Join(rep.Warnings, "\n"), c.warn) {
			t.Errorf("%s: warnings %v, want %q", c.name, rep.Warnings, c.warn)
		}
	}
	// without --out, agent outputs are not checked but paths are
	rep, _ := DocumentWith("ledger", []byte(unit(`["C9"]`, `["circuit/other.go"]`)), Options{})
	if j := strings.Join(rep.Errors, "\n"); strings.Contains(j, "no saved output") || !strings.Contains(j, "own file") {
		t.Errorf("no --out: %v", rep.Errors)
	}
}

// trustDoc is one trusted-party record: an owner who swaps the verifier.
func trustDoc(verdict, severity, extra, trustExtra string) string {
	body := `"severity": "` + severity + `", "confidence": 70, "blockers": ["Is the owner a timelocked multisig, and who holds its keys?"], "validation_plan": "Read the deployed owner on chain."`
	switch verdict {
	case "lead":
		body = `"code_smells": ["owner-only setter"], "unverified": "who holds the key"`
	case "rejected":
		body = `"reason": "the setter is internal", "refuting_location": {"file": "contracts/Vault.sol", "line": 9, "scope": "Vault"}`
	case "confirmed":
		body = `"severity": "` + severity + `", "confidence": 70, "evidence": "ANALYSIS", "proof": "anyone calls initialize first", "impact": "drains the vault", "gates": {"executes": "y", "reachable": "y", "unprivileged": "initializer is ungated", "impact": "funds"}`
	}
	return `{"schema_version": "1", "repo": "vault", "run_id": "20261029-101500", "profile": "standard", "records": [{
	  "fingerprint": "Vault|setVerifier|trusted-verifier-swap", "verdict": "` + verdict + `", "title": "Owner swaps the verifier",
	  "layer": "integration", "bug_class": "trusted-verifier-swap",
	  "location": {"file": "contracts/Vault.sol", "line": 20, "scope": "Vault.setVerifier"},
	  "detected_by": ["T1"], "description": "The owner replaces the verifier at any time.", ` + body + extra + `,
	  "trust": {"party": "owner of Vault", "role": "owner", "power": "replaces the verifier", "breaks": ["soundness", "funds"],
	            "assumption": "the owner is a timelocked multisig"` + trustExtra + `}}]}`
}

func TestTrustedPartyRules(t *testing.T) {
	cases := []struct {
		name, doc, wantErr, wantWarn string
	}{
		{"needs_validation high", trustDoc("needs_validation", "high", "", ""), "", ""},
		{"lead without reason", trustDoc("lead", "", "", ""), "is not a lead", ""},
		{"lead with reason", trustDoc("lead", "", "", `, "lead_reason": "the gate is in an unscanned base contract"`), "", ""},
		{"low power over funds", trustDoc("needs_validation", "low", "", ""), "at least medium", ""},
		{"medium without mitigation", trustDoc("needs_validation", "medium", "", ""), "needs trust.mitigation", ""},
		{"medium with mitigation", trustDoc("needs_validation", "medium", "", `, "mitigation": "owner is TimelockController (deploy/Deploy.s.sol:14)"`), "", ""},
		{"accepted without source", trustDoc("needs_validation", "high", "", `, "accepted": true`), "needs trust.source", ""},
		{"accepted with source", trustDoc("needs_validation", "high", "", `, "accepted": true, "source": "zk-audit.md:12"`), "", ""},
		{"accepted lead", trustDoc("lead", "", "", `, "accepted": true, "source": "zk-audit.md:12", "lead_reason": "x"`), "accepted risk", ""},
		{"bad source", trustDoc("needs_validation", "high", "", `, "accepted": true, "source": "README.md:3"`), "does not match", ""},
		{"confirmed amplifier", trustDoc("confirmed", "critical", "", ""), "", ""},
		{"rejected", trustDoc("rejected", "", "", ""), "", ""},
		{"blocker without party", strings.Replace(trustDoc("needs_validation", "high", "", ""), "Is the owner a timelocked multisig, and who holds its keys?", "Which address is deployed?", 1), "", "no blocker names the trusted party"},
		{"trusted bug_class without trust", strings.Replace(trustDoc("lead", "", "", ""), `,
	  "trust": {"party": "owner of Vault", "role": "owner", "power": "replaces the verifier", "breaks": ["soundness", "funds"],
	            "assumption": "the owner is a timelocked multisig"}`, "", 1), "", "has no trust object"},
	}
	for _, c := range cases {
		rep, err := Document("findings", []byte(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		errs, warns := strings.Join(rep.Errors, "\n"), strings.Join(rep.Warnings, "\n")
		if c.wantErr == "" && !rep.OK() {
			t.Errorf("%s: unexpected errors: %s", c.name, errs)
		}
		if c.wantErr != "" && !strings.Contains(errs, c.wantErr) {
			t.Errorf("%s: want error %q, got %q", c.name, c.wantErr, errs)
		}
		if c.wantWarn != "" && !strings.Contains(warns, c.wantWarn) {
			t.Errorf("%s: want warning %q, got %q", c.name, c.wantWarn, warns)
		}
	}
}

func TestCalibrationAnchors(t *testing.T) {
	base := trustDoc("needs_validation", "high", "", "")
	cases := []struct{ name, doc, wantErr, wantWarn string }{
		{"no anchor warns", base, "", "no calibration anchor"},
		{"fitting anchor", strings.Replace(base, `"verdict": "needs_validation",`, `"verdict": "needs_validation", "calibration": "SC-TRUST-SOUNDNESS",`, 1), "", ""},
		{"unknown anchor", strings.Replace(base, `"verdict": "needs_validation",`, `"verdict": "needs_validation", "calibration": "SC-NOPE",`, 1), "unknown calibration anchor", ""},
		{"severity outside anchor", strings.Replace(base, `"verdict": "needs_validation",`, `"verdict": "needs_validation", "calibration": "SC-TRUST-HYGIENE",`, 1), "severity high is not allowed by SC-TRUST-HYGIENE", ""},
		{"verdict outside anchor", strings.Replace(base, `"verdict": "needs_validation",`, `"verdict": "needs_validation", "calibration": "SC-MASKED-BYPASS",`, 1), "verdict needs_validation is not allowed", ""},
	}
	for _, c := range cases {
		rep, err := Document("findings", []byte(c.doc))
		if err != nil {
			t.Fatal(err)
		}
		errs, warns := strings.Join(rep.Errors, "\n"), strings.Join(rep.Warnings, "\n")
		if c.wantErr == "" && !rep.OK() {
			t.Errorf("%s: unexpected errors %s", c.name, errs)
		}
		if c.wantErr != "" && !strings.Contains(errs, c.wantErr) {
			t.Errorf("%s: want error %q, got %q", c.name, c.wantErr, errs)
		}
		if c.wantWarn != "" && !strings.Contains(warns, c.wantWarn) {
			t.Errorf("%s: want warning %q, got %q", c.name, c.wantWarn, warns)
		}
	}
}

// With threat-model.json in the output directory, an accepted risk must
// cite the line of an accepted risk or of a party marked trusted.
func TestAcceptedRiskAgainstThreatModel(t *testing.T) {
	out := t.TempDir()
	accepted := func(line string) []byte {
		return []byte(trustDoc("needs_validation", "high", "", `, "accepted": true, "source": "zk-audit.md:`+line+`"`))
	}
	// no threat model: a warning only
	rep, err := DocumentWith("findings", accepted("12"), Options{Out: out})
	if err != nil || !rep.OK() || !strings.Contains(strings.Join(rep.Warnings, "\n"), "no threat-model.json") {
		t.Fatalf("without threat-model.json: %v %+v", err, rep)
	}
	tm := `{"schema_version": "1", "source": "zk-audit.md", "sha256": "` + strings.Repeat("0", 64) + `",
	  "scope": {"in": [], "out": []},
	  "trusted_parties": [{"party": "owner", "trust": "trusted", "powers": "", "notes": "", "line": 12},
	                      {"party": "tallier", "trust": "bounded", "powers": "", "notes": "x", "line": 13}],
	  "properties": [], "accepted_risks": [{"id": "AR-1", "party": "owner", "risk": "swaps the verifier", "notes": "", "line": 20}],
	  "prior_findings": [], "deployment": [], "warnings": []}`
	if rep, _ := Document("threat-model", []byte(tm)); !rep.OK() {
		t.Fatalf("threat-model.json fixture: %v", rep.Errors)
	}
	os.WriteFile(filepath.Join(out, "threat-model.json"), []byte(tm), 0o644)
	for line, ok := range map[string]bool{"12": true, "20": true, "13": false, "30": false} {
		rep, err := DocumentWith("findings", accepted(line), Options{Out: out})
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK() != ok {
			t.Errorf("zk-audit.md:%s: ok %v, errors %v", line, rep.OK(), rep.Errors)
		}
	}
	// the top-level accepted_risks entries too
	doc := strings.Replace(trustDoc("needs_validation", "high", "", ""), `"records": [`, `"accepted_risks": [{"party": "tallier", "risk": "posts a late root", "source": "zk-audit.md:13"}], "records": [`, 1)
	if rep, _ := DocumentWith("findings", []byte(doc), Options{Out: out}); rep.OK() {
		t.Error("accepted_risks entry citing a bounded party passed")
	}
}
