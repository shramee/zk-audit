package memory

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func record(fp, verdict string) string {
	common := `"fingerprint":"` + fp + `","verdict":"` + verdict + `","title":"t ` + fp + `","layer":"circuit","bug_class":"x",
	 "location":{"file":"c/vote.go","line":3,"scope":"S"},"detected_by":["C1"],"description":"d"`
	switch verdict {
	case "confirmed":
		return `{` + common + `,"severity":"low","confidence":60,"evidence":"ANALYSIS","proof":"p","impact":"i","gates":{"executes":"e","reachable":"r","unprivileged":"u","impact":"i"}}`
	case "rejected":
		return `{` + common + `,"reason":"blocked","refuting_location":{"file":"c/vote.go","line":4,"scope":"S"}}`
	}
	return `{` + common + `,"code_smells":["s"],"unverified":"u"}`
}

func doc(records ...string) []byte {
	if len(records) == 0 {
		return []byte(`{"schema_version":"1","repo":"r","run_id":"20261029-101010","profile":"deep","no_findings":true,"no_findings_reason":"pass found nothing new","records":[]}`)
	}
	return []byte(`{"schema_version":"1","repo":"r","run_id":"20261029-101010","profile":"deep","records":[` + strings.Join(records, ",") + `]}`)
}

type cum struct {
	Records []struct {
		Fingerprint string `json:"fingerprint"`
		RunTag      string `json:"run_tag"`
		Seen        struct{ Passes, Of int }
	} `json:"records"`
}

func readCum(t *testing.T, out string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(out + "/findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var c cum
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, r := range c.Records {
		m[r.Fingerprint] = r.RunTag + " " + itoa(r.Seen.Passes) + "/" + itoa(r.Seen.Of)
	}
	return m
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

const (
	fpA = "Vote|tally|hint-output-unconstrained"
	fpB = "Vote|owner|owner-gate"
	fpC = "Ballot|cast|voter-not-bound"
)

func TestLoopPasses(t *testing.T) {
	out := t.TempDir()
	if _, err := Merge(out, 1, doc(record(fpA, "confirmed")), 0, false); err == nil {
		t.Fatal("merge without init accepted")
	}
	if _, err := Init(out, 3); err != nil {
		t.Fatal(err)
	}
	p1, err := Merge(out, 1, doc(record(fpA, "confirmed"), record(fpB, "rejected")), 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.New) != 2 || p1.Stop {
		t.Fatalf("pass 1: %+v", p1)
	}
	if got := readCum(t, out); got[fpA] != "NEW 1/1" || got[fpB] != "NEW 1/1" {
		t.Errorf("after pass 1: %v", got)
	}
	if _, err := Merge(out, 3, doc(), 0, true); err == nil {
		t.Error("out-of-order pass accepted")
	}
	p2, err := Merge(out, 2, doc(record(fpA, "confirmed"), record(fpC, "lead")), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p2.New, ",") != fpC || strings.Join(p2.Known, ",") != fpA || p2.Stop {
		t.Fatalf("pass 2: %+v", p2)
	}
	// re-merging the last pass replaces it
	if p2b, err := Merge(out, 2, doc(record(fpA, "confirmed"), record(fpC, "lead")), 1, true); err != nil || len(p2b.New) != 1 {
		t.Fatalf("re-merge: %+v %v", p2b, err)
	}
	got := readCum(t, out)
	if got[fpA] != "KNOWN 2/2" || got[fpB] != "KNOWN 1/2" || got[fpC] != "NEW 1/2" {
		t.Errorf("after pass 2: %v", got)
	}
	m, _, _ := Load(out)
	known := m.Known()
	for _, fp := range []string{fpA, fpB, fpC} {
		if !strings.Contains(known, fp) {
			t.Errorf("known list lacks %s", fp)
		}
	}
	if !strings.Contains(known, "| rejected |") || !strings.Contains(m.Status(), "2/2 passes") {
		t.Errorf("known/status:\n%s\n%s", known, m.Status())
	}
	p3, err := Merge(out, 3, doc(), 0, true)
	if err != nil || !p3.Stop || !strings.Contains(p3.Reason, "all 3 planned passes") {
		t.Fatalf("pass 3: %+v %v", p3, err)
	}
	if _, err := Merge(out, 4, doc(), 0, true); err == nil {
		t.Error("merge after the stop accepted")
	}
}

func TestStopRule(t *testing.T) {
	out := t.TempDir()
	Init(out, 3)
	Merge(out, 1, doc(record(fpA, "confirmed")), 0, true)
	// nothing new, but the critic still reports missing units: continue
	p2, err := Merge(out, 2, doc(record(fpA, "confirmed")), 3, true)
	if err != nil || p2.Stop {
		t.Fatalf("missing units must keep the loop going: %+v %v", p2, err)
	}
	p2, err = Merge(out, 2, doc(record(fpA, "confirmed")), 0, true)
	if err != nil || !p2.Stop || !strings.Contains(p2.Reason, "no new fingerprint and the critic reported no missing unit") {
		t.Fatalf("stop rule: %+v %v", p2, err)
	}
	if _, err := Merge(out, 3, doc(), 0, true); err == nil || !strings.Contains(err.Error(), "stopped the loop") {
		t.Errorf("pass after stop: %v", err)
	}
}

func TestMergeRejectsInvalidFindings(t *testing.T) {
	out := t.TempDir()
	Init(out, 2)
	if _, err := Merge(out, 1, []byte(`{"schema_version":"1","records":[]}`), 0, false); err == nil {
		t.Error("invalid pass findings accepted")
	}
	if _, err := Init(out, 0); err == nil {
		t.Error("zero passes accepted")
	}
}

func TestMissingUnits(t *testing.T) {
	for in, want := range map[string]int{
		`{"missing_units":[]}`: 0,
		"Here you go:\n```json\n{\"missing_units\": [{\"id\": \"a\"}, {\"id\": \"b\"}]}\n```\n": 2,
	} {
		if n, err := MissingUnits([]byte(in)); err != nil || n != want {
			t.Errorf("%q: %d %v", in, n, err)
		}
	}
	if _, err := MissingUnits([]byte("all good")); err == nil {
		t.Error("prose accepted")
	}
}
