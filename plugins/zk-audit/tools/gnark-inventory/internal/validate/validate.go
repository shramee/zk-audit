// Package validate checks findings.json, coverage-ledger.json and stack.json
// against the plugin's JSON schemas and then against semantic rules that a
// schema cannot express. Every check fails when it inspects zero items.
package validate

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/jsonschema"
)

// Schemas are copies of plugins/zk-audit/schemas/*.json; a unit test keeps
// them identical.
//
//go:embed schemas/*.json
var Schemas embed.FS

// Kinds lists the document kinds and their schema file names.
var Kinds = map[string]string{
	"findings": "findings.schema.json",
	"ledger":   "ledger.schema.json",
	"stack":    "stack.schema.json",
}

// Report is the result of one validation.
type Report struct {
	Kind     string   `json:"kind"`
	Items    int      `json:"items_inspected"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// OK reports whether validation passed.
func (r *Report) OK() bool { return len(r.Errors) == 0 }

// Document validates doc as kind.
func Document(kind string, doc []byte) (*Report, error) {
	name, ok := Kinds[kind]
	if !ok {
		return nil, fmt.Errorf("unknown kind %q (want findings, ledger or stack)", kind)
	}
	raw, err := Schemas.ReadFile("schemas/" + name)
	if err != nil {
		return nil, err
	}
	sch, err := jsonschema.Compile(raw)
	if err != nil {
		return nil, err
	}
	rep := &Report{Kind: kind, Errors: []string{}, Warnings: []string{}}
	errs, _, err := sch.ValidateBytes(doc)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return rep, nil
	}
	for _, e := range errs {
		rep.Errors = append(rep.Errors, "schema: "+e.Error())
	}
	switch kind {
	case "findings":
		semanticFindings(doc, rep)
	case "ledger":
		semanticLedger(doc, rep)
	case "stack":
		rep.Items = 1
	}
	if len(rep.Errors) > 200 {
		n := len(rep.Errors)
		rep.Errors = append(rep.Errors[:200], fmt.Sprintf("... %d more errors", n-200))
	}
	return rep, nil
}

type record struct {
	Fingerprint string          `json:"fingerprint"`
	Verdict     string          `json:"verdict"`
	Severity    string          `json:"severity"`
	Confidence  *int            `json:"confidence"`
	Evidence    string          `json:"evidence"`
	Fix         json.RawMessage `json:"fix"`
	Poc         *struct {
		Path   string `json:"path"`
		Result string `json:"result"`
	} `json:"poc"`
	Layer    string   `json:"layer"`
	Proof    string   `json:"proof"`
	Chain    []string `json:"chain"`
	Detected []string `json:"detected_by"`
}

type findingsDoc struct {
	NoFindings       bool     `json:"no_findings"`
	NoFindingsReason string   `json:"no_findings_reason"`
	Records          []record `json:"records"`
}

func semanticFindings(doc []byte, rep *Report) {
	var d findingsDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		rep.Errors = append(rep.Errors, "decode: "+err.Error())
		return
	}
	rep.Items = len(d.Records)
	if len(d.Records) == 0 {
		if !d.NoFindings || strings.TrimSpace(d.NoFindingsReason) == "" {
			rep.Errors = append(rep.Errors, "zero records inspected: a findings file with no records must set no_findings: true and a no_findings_reason")
		} else {
			rep.Items = 1 // the explicit empty statement is the inspected item
		}
		return
	}
	if d.NoFindings {
		rep.Errors = append(rep.Errors, "no_findings is true but records are present")
	}
	seen := map[string]bool{}
	fps := map[string]bool{}
	for _, r := range d.Records {
		fps[r.Fingerprint] = true
	}
	for i, r := range d.Records {
		at := fmt.Sprintf("records[%d] (%s)", i, r.Fingerprint)
		key := r.Fingerprint + "#" + r.Verdict
		if seen[r.Fingerprint] {
			rep.Errors = append(rep.Errors, at+": duplicate fingerprint; dedup must merge records with the same group_key")
		}
		seen[r.Fingerprint] = true
		_ = key
		if r.Verdict != "confirmed" {
			continue
		}
		if r.Evidence == "POC" {
			if r.Poc == nil || r.Poc.Result != "demonstrated" {
				rep.Errors = append(rep.Errors, at+": evidence POC requires poc.result \"demonstrated\"; otherwise use ANALYSIS")
			}
		}
		if r.Evidence == "ANALYSIS" && r.Poc != nil && r.Poc.Result == "demonstrated" {
			rep.Warnings = append(rep.Warnings, at+": poc demonstrated but evidence is ANALYSIS")
		}
		if r.Confidence != nil && *r.Confidence >= 80 && len(r.Fix) == 0 {
			rep.Errors = append(rep.Errors, at+": confidence >= 80 requires a fix")
		}
		if r.Confidence != nil && *r.Confidence < 50 {
			rep.Warnings = append(rep.Warnings, at+": confirmed with confidence < 50; consider needs_validation")
		}
		for _, c := range r.Chain {
			if !fps[c] {
				rep.Errors = append(rep.Errors, at+": chain references unknown fingerprint "+c)
			}
		}
	}
}

type unit struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Class              string   `json:"class"`
	Status             string   `json:"status"`
	AgentIDs           []string `json:"agent_ids"`
	ReviewedPaths      []string `json:"reviewed_paths"`
	ResultFingerprints []string `json:"result_fingerprints"`
	Reason             string   `json:"reason"`
}

type ledgerDoc struct {
	Units []unit `json:"units"`
}

func semanticLedger(doc []byte, rep *Report) {
	var d ledgerDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		rep.Errors = append(rep.Errors, "decode: "+err.Error())
		return
	}
	rep.Items = len(d.Units)
	if len(d.Units) == 0 {
		rep.Errors = append(rep.Errors, "zero units inspected: a coverage ledger must contain at least one unit")
		return
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for i, u := range d.Units {
		at := fmt.Sprintf("units[%d] (%s)", i, u.ID)
		if seen[u.ID] {
			rep.Errors = append(rep.Errors, at+": duplicate unit id")
		}
		seen[u.ID] = true
		if !strings.HasPrefix(u.ID, u.Kind+":") {
			rep.Errors = append(rep.Errors, at+": id must start with its kind \""+u.Kind+":\"")
		}
		if !strings.HasSuffix(u.ID, "|"+u.Class) {
			rep.Errors = append(rep.Errors, at+": id must end with its class \"|"+u.Class+"\"")
		}
		counts[u.Status]++
		switch u.Status {
		case "covered":
			if len(u.AgentIDs) == 0 || len(u.ReviewedPaths) == 0 {
				rep.Errors = append(rep.Errors, at+": covered units need agent_ids and reviewed_paths")
			}
		case "candidate":
			if len(u.ResultFingerprints) == 0 {
				rep.Errors = append(rep.Errors, at+": candidate units need result_fingerprints")
			}
			if len(u.AgentIDs) == 0 {
				rep.Errors = append(rep.Errors, at+": candidate units need agent_ids")
			}
		case "blocked", "deferred", "not_applicable", "out_of_scope":
			if strings.TrimSpace(u.Reason) == "" {
				rep.Errors = append(rep.Errors, at+": status "+u.Status+" needs a reason")
			}
		}
	}
	var parts []string
	for k, v := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(parts)
	rep.Warnings = append(rep.Warnings, "status counts: "+strings.Join(parts, " "))
}
