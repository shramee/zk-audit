// Package validate checks findings.json, coverage-ledger.json and stack.json
// against the plugin's JSON schemas and then against semantic rules that a
// schema cannot express. Every check fails when it inspects zero items.
package validate

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/jsonschema"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// Schemas are copies of plugins/zk-audit/skills/zk-audit/schemas/*.json; a unit test keeps
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
	Info     []string `json:"info"`
}

// OK reports whether validation passed.
func (r *Report) OK() bool { return len(r.Errors) == 0 }

// Options add checks against the audit output directory.
type Options struct {
	// Out is the audit output directory. When set, findings must point
	// poc.path at a file under <out>/pocs/, and covered or candidate ledger
	// units must have their agents' outputs in <out>/agents/.
	Out string
}

// Document validates doc as kind.
func Document(kind string, doc []byte) (*Report, error) {
	return DocumentWith(kind, doc, Options{})
}

// DocumentWith validates doc as kind with the extra checks of opt.
func DocumentWith(kind string, doc []byte, opt Options) (*Report, error) {
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
	rep := &Report{Kind: kind, Errors: []string{}, Warnings: []string{}, Info: []string{}}
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
		semanticFindings(doc, rep, opt)
	case "ledger":
		semanticLedger(doc, rep, opt)
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
		Path         string `json:"path"`
		Result       string `json:"result"`
		Demonstrates string `json:"demonstrates"`
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

func semanticFindings(doc []byte, rep *Report, opt Options) {
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
	referenced := map[string]bool{}
	for i, r := range d.Records {
		at := fmt.Sprintf("records[%d] (%s)", i, r.Fingerprint)
		if seen[r.Fingerprint] {
			rep.Errors = append(rep.Errors, at+": duplicate fingerprint; dedup must merge records with the same group_key")
		}
		seen[r.Fingerprint] = true
		if r.Poc != nil {
			checkPoC(at, r.Evidence == "POC", r.Poc.Path, r.Poc.Result, r.Poc.Demonstrates, opt, rep, referenced)
		}
		if r.Verdict != "confirmed" {
			continue
		}
		if r.Evidence == "POC" {
			switch {
			case r.Poc == nil:
				rep.Errors = append(rep.Errors, at+": evidence POC requires a poc object with result \"demonstrated\"; otherwise use ANALYSIS")
			case r.Poc.Result == "demonstrated_on_model":
				rep.Errors = append(rep.Errors, at+": a PoC on a model circuit (demonstrated_on_model) keeps evidence ANALYSIS")
			case r.Poc.Result != "demonstrated":
				rep.Errors = append(rep.Errors, at+": evidence POC requires poc.result \"demonstrated\"; otherwise use ANALYSIS")
			}
		}
		if r.Evidence == "ANALYSIS" && r.Poc != nil && r.Poc.Result == "demonstrated" {
			rep.Warnings = append(rep.Warnings, at+": poc demonstrated but evidence is ANALYSIS; use POC, or demonstrated_on_model if the PoC runs a model of the circuit")
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
	if opt.Out != "" {
		for _, f := range pocFiles(opt.Out) {
			if !referenced[f] {
				rep.Warnings = append(rep.Warnings, "pocs/"+f+" is not the poc.path of any record; attach it to its record (a demoted record keeps its poc) or delete it")
			}
		}
	}
}

// pocFiles lists the files under <out>/pocs/ (slash paths relative to it),
// without the generated MANIFEST.json.
func pocFiles(out string) []string {
	var files []string
	root := filepath.Join(out, "pocs")
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel = filepath.ToSlash(rel); rel != "MANIFEST.json" {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	return files
}

// PoCPath resolves a record's poc.path ("pocs/<file>", relative to the
// output directory, or absolute) to a slash path relative to <out>/pocs. ok
// is false when it leaves <out>/pocs.
func PoCPath(out, p string) (string, bool) {
	root, err := filepath.Abs(filepath.Join(out, "pocs"))
	if err != nil {
		return "", false
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(out, filepath.FromSlash(p))
	}
	abs, err = filepath.Abs(abs)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// checkPoC checks one record's poc object. Errors: a demonstrated PoC (or
// any PoC behind evidence POC) whose file is not under <out>/pocs/. Warnings:
// a missing file for a PoC that did not demonstrate anything, and a
// demonstrated PoC that does not say which property it breaks.
func checkPoC(at string, evidencePoC bool, path, result, demonstrates string, opt Options, rep *Report, referenced map[string]bool) {
	demonstrated := result == "demonstrated" || result == "demonstrated_on_model"
	if demonstrated && demonstrates == "" {
		rep.Warnings = append(rep.Warnings, at+": poc.demonstrates is missing; say soundness (a false statement accepted) or completeness (an honest statement rejected)")
	}
	if opt.Out == "" {
		return
	}
	rel, ok := PoCPath(opt.Out, path)
	if !ok {
		rep.Errors = append(rep.Errors, at+": poc.path "+path+" is not under <out>/pocs/")
		return
	}
	referenced[rel] = true
	real, err := filepath.EvalSymlinks(filepath.Join(opt.Out, "pocs", filepath.FromSlash(rel)))
	st, serr := os.Stat(real)
	switch {
	case err != nil || serr != nil || !st.Mode().IsRegular():
		msg := at + ": poc.path " + path + " does not exist under " + filepath.Join(opt.Out, "pocs")
		if demonstrated || evidencePoC {
			rep.Errors = append(rep.Errors, msg)
		} else {
			rep.Warnings = append(rep.Warnings, msg)
		}
	default:
		if root, err := filepath.EvalSymlinks(filepath.Join(opt.Out, "pocs")); err == nil {
			if r, err := filepath.Rel(root, real); err != nil || strings.HasPrefix(r, "..") {
				rep.Errors = append(rep.Errors, at+": poc.path "+path+" is a symlink out of <out>/pocs/")
			}
		}
	}
}

type unit struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Class              string   `json:"class"`
	Lenses             []string `json:"lenses"`
	Paths              []string `json:"paths"`
	Status             string   `json:"status"`
	AgentIDs           []string `json:"agent_ids"`
	ReviewedPaths      []string `json:"reviewed_paths"`
	ResultFingerprints []string `json:"result_fingerprints"`
	Reason             string   `json:"reason"`
}

type ledgerDoc struct {
	Units []unit `json:"units"`
}

func semanticLedger(doc []byte, rep *Report, opt Options) {
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
	set := profile.Load()
	classes := set.LedgerClasses()
	lenses := set.LedgerLenses()
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
		if _, ok := classes[u.Class]; !ok && u.Class != "" {
			rep.Errors = append(rep.Errors, at+": class \""+u.Class+"\" is owned by no lens in profiles.json")
		}
		for _, l := range u.Lenses {
			if !lenses[l] {
				rep.Errors = append(rep.Errors, at+": lens \""+l+"\" is not defined in profiles.json")
			}
		}
		counts[u.Status]++
		for _, p := range u.ReviewedPaths {
			c := filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))
			if filepath.IsAbs(p) || c == ".." || strings.HasPrefix(c, "../") {
				rep.Errors = append(rep.Errors, at+": reviewed_paths entry "+p+" is not a repository-relative path")
			}
		}
		if u.Status == "covered" || u.Status == "candidate" {
			for _, a := range u.AgentIDs {
				if !set.AgentKnown(a) {
					rep.Warnings = append(rep.Warnings, at+": agent id "+a+" is no lens or critic in profiles.json; record orchestrator work in notes, not as an agent")
				}
				if opt.Out != "" && !AgentOutputExists(opt.Out, a) {
					rep.Errors = append(rep.Errors, at+": agent "+a+" has no saved output in "+filepath.Join(opt.Out, "agents", SafeName(a)+".md")+" (agents save); a unit is covered only by an agent whose output exists")
				}
			}
		}
		switch u.Status {
		case "covered":
			if len(u.AgentIDs) == 0 || len(u.ReviewedPaths) == 0 {
				rep.Errors = append(rep.Errors, at+": covered units need agent_ids and reviewed_paths")
			} else if own := unitFiles(u.Paths); len(own) > 0 && !anyIn(u.ReviewedPaths, own) {
				rep.Errors = append(rep.Errors, at+": reviewed_paths "+strings.Join(u.ReviewedPaths, ", ")+" do not include the unit's own file ("+strings.Join(own, ", ")+")")
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
	rep.Info = append(rep.Info, "status counts: "+strings.Join(parts, " "))
}

// SafeName maps an agent id (C1@circuit/vote) to the file name used under
// bundles/ and agents/.
func SafeName(id string) string {
	return strings.NewReplacer("/", "_", "@", "__", " ", "_").Replace(id)
}

// AgentOutputExists reports whether <out>/agents/<id>.md (or its safe name)
// is a non-empty regular file.
func AgentOutputExists(out, id string) bool {
	for _, n := range []string{SafeName(id), id} {
		if strings.ContainsAny(n, "/\\") || strings.HasPrefix(n, ".") {
			continue
		}
		if st, err := os.Stat(filepath.Join(out, "agents", n+".md")); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
			return true
		}
	}
	return false
}

// unitFiles returns the files of a unit's paths ("file:line" or "file"),
// without "?" placeholders.
func unitFiles(paths []string) []string {
	var out []string
	for _, p := range paths {
		if p == "?" || p == "" {
			continue
		}
		if i := strings.LastIndexByte(p, ':'); i > 0 && isDigits(p[i+1:]) {
			p = p[:i]
		}
		out = append(out, filepath.ToSlash(filepath.Clean(filepath.FromSlash(p))))
	}
	return out
}

func anyIn(reviewed, own []string) bool {
	for _, r := range reviewed {
		r = filepath.ToSlash(filepath.Clean(filepath.FromSlash(r)))
		for _, o := range own {
			if r == o || strings.HasPrefix(o, strings.TrimSuffix(r, "/")+"/") {
				return true
			}
		}
	}
	return false
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
