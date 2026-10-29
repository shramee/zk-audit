// Package verifier checks a ZK application's Solidity verifier against what
// gnark produces: the ABI a caller's interface expects versus the verifier
// gnark exports for the pinned version and backend (abi.go), the structure
// and verifying-key constants of two verifier sources (diff.go, vk.go), the
// deployed runtime bytecode (bytecode.go), a regenerated verifier built by
// running the target's own gnark in the sandbox (regen.go), and the setup
// ceremony artefacts in the repository (ceremony.go).
package verifier

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/keccak"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

//go:embed templates.json
var templatesRaw []byte

// Template is the ABI of the verifier gnark exports for a backend over a
// version range [From, To).
type Template struct {
	Backend         string   `json:"backend"`
	From            string   `json:"from"`
	To              string   `json:"to"`
	Contract        string   `json:"contract"`
	Function        string   `json:"function"`
	Params          []string `json:"params"`
	Returns         []string `json:"returns"`
	WithCommitments []string `json:"with_commitments,omitempty"`
	Compressed      *struct {
		Function        string   `json:"function"`
		Params          []string `json:"params"`
		WithCommitments []string `json:"with_commitments,omitempty"`
	} `json:"compressed,omitempty"`
	OnFailure   string `json:"on_failure"`
	Commitments string `json:"commitments"`
	Source      string `json:"source"`
}

type templateSet struct {
	Comment       string     `json:"$comment"`
	SchemaVersion string     `json:"schema_version"`
	Templates     []Template `json:"templates"`
}

// Templates returns the embedded template table.
func Templates() []Template {
	var s templateSet
	if err := json.Unmarshal(templatesRaw, &s); err != nil {
		panic("templates.json: " + err.Error())
	}
	return s.Templates
}

// TemplateFor returns the template of a backend at a gnark version.
func TemplateFor(backend, version string) (Template, bool) {
	v := version
	if !semver.IsValid(v) {
		return Template{}, false
	}
	for _, t := range Templates() {
		if t.Backend != backend {
			continue
		}
		if semver.Compare(v, t.From) >= 0 && (t.To == "" || semver.Compare(v, t.To) < 0) {
			return t, true
		}
	}
	return Template{}, false
}

// Expected is one function signature gnark exports.
type Expected struct {
	Signature string   `json:"signature"`
	Selector  string   `json:"selector"`
	Returns   []string `json:"returns"`
	Variant   string   `json:"variant"`
}

// Expect instantiates the template's verify signatures for n public inputs
// (n < 0: unknown, the input array length then stays N) and k commitments
// (k < 0: both the plain and the one-commitment variant).
func (t Template) Expect(n, k int) []Expected {
	inst := func(ps []string, kk int) string {
		var out []string
		for _, p := range ps {
			p = strings.ReplaceAll(p, "[2K]", "["+strconv.Itoa(2*kk)+"]")
			p = strings.ReplaceAll(p, "[K]", "["+strconv.Itoa(kk)+"]")
			if n >= 0 {
				p = strings.ReplaceAll(p, "[N]", "["+strconv.Itoa(n)+"]")
			}
			out = append(out, p)
		}
		return strings.Join(out, ",")
	}
	var out []Expected
	add := func(fn string, ps []string, kk int, variant string) {
		sig := fn + "(" + inst(ps, kk) + ")"
		e := Expected{Signature: sig, Returns: t.Returns, Variant: variant}
		if !strings.Contains(sig, "[N]") {
			e.Selector = keccak.Selector(sig)
		}
		for _, x := range out {
			if x.Signature == sig {
				return
			}
		}
		out = append(out, e)
	}
	if k <= 0 {
		add(t.Function, t.Params, 0, "no commitments")
	}
	if len(t.WithCommitments) > 0 && k != 0 {
		kk := k
		if kk < 0 {
			kk = 1
		}
		add(t.Function, t.WithCommitments, kk, fmt.Sprintf("%d commitment(s)", kk))
	}
	if t.Compressed != nil {
		if k <= 0 {
			add(t.Compressed.Function, t.Compressed.Params, 0, "compressed proof")
		}
		if len(t.Compressed.WithCommitments) > 0 && k != 0 {
			kk := k
			if kk < 0 {
				kk = 1
			}
			add(t.Compressed.Function, t.Compressed.WithCommitments, kk, fmt.Sprintf("compressed proof, %d commitment(s)", kk))
		}
	}
	return out
}

// Gnark is what the ABI check knows about the target's gnark use.
type Gnark struct {
	Versions    []string
	Backends    []string
	Commitments bool
	// PublicCounts are the static public-input counts of production
	// circuits.
	PublicCounts []int
}

// Comparison is one side the caller is checked against.
type Comparison struct {
	// Against: repo-verifier or gnark-template.
	Against   string   `json:"against"`
	Name      string   `json:"name"`
	Signature string   `json:"signature,omitempty"`
	Selector  string   `json:"selector,omitempty"`
	Returns   []string `json:"returns"`
	OnFailure string   `json:"on_failure,omitempty"`
	// Status: match, selector-mismatch, return-mismatch, bool-ignored,
	// width-mismatch, unknown.
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ABICheck is the check of one verification call site.
type ABICheck struct {
	Site     string `json:"site"`
	Caller   string `json:"caller"`
	Via      string `json:"via"`
	Callee   string `json:"callee"`
	Declared string `json:"declared_on,omitempty"`
	// Signature and Selector as the caller encodes the call; Returns what it
	// decodes.
	Signature  string       `json:"signature,omitempty"`
	Selector   string       `json:"selector,omitempty"`
	Returns    []string     `json:"returns"`
	ResultUsed bool         `json:"result_used"`
	Against    []Comparison `json:"against"`
	// Status: match (every comparison matches), mismatch (at least one
	// does not), unknown (nothing to compare with).
	Status string `json:"status"`
}

// TemplateCheck compares an in-repository verifier with the template the
// pinned gnark version exports.
type TemplateCheck struct {
	Verifier string `json:"verifier"`
	Site     string `json:"site"`
	Kind     string `json:"kind"`
	Template string `json:"template,omitempty"`
	Pinned   string `json:"pinned_gnark,omitempty"`
	// Status: match, mismatch, not-gnark, unknown.
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ABIReport is the result of CheckABI.
type ABIReport struct {
	Calls     []ABICheck      `json:"calls"`
	Verifiers []TemplateCheck `json:"verifiers"`
}

// Mismatches counts call sites with a mismatch and verifiers that differ
// from the pinned template.
func (r *ABIReport) Mismatches() int {
	n := 0
	for _, c := range r.Calls {
		if c.Status == "mismatch" {
			n++
		}
	}
	for _, v := range r.Verifiers {
		if v.Status == "mismatch" {
			n++
		}
	}
	return n
}

var reFixedLen = regexp.MustCompile(`\[(\d+)\]$`)

func fixedLen(t string) int {
	if m := reFixedLen.FindStringSubmatch(t); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return -1
}

// CheckABI compares every external verification call with the verifiers in
// the repository it can reach and with the verifier the pinned gnark
// version exports for each backend in use.
func CheckABI(res *solidity.Result, g Gnark) *ABIReport {
	rep := &ABIReport{Calls: []ABICheck{}, Verifiers: []TemplateCheck{}}
	if res == nil {
		return rep
	}
	versions := validVersions(g.Versions)
	for _, vc := range res.VerifyCalls {
		switch vc.Via {
		case "internal", "inherited", "library", "using":
			// no ABI boundary: a jump inside the caller's own code
			continue
		}
		c := ABICheck{Site: fmt.Sprintf("%s:%d", vc.File, vc.Line), Caller: vc.Contract + "." + vc.Function, Via: vc.Via,
			Callee: vc.Callee, ResultUsed: vc.ResultUsed, Returns: []string{}, Against: []Comparison{}}
		var params []string
		switch {
		case vc.LowLevel != nil:
			c.Signature, c.Selector = vc.LowLevel.Signature, vc.LowLevel.Selector
			if vc.LowLevel.DecodesBool {
				c.Returns = []string{"bool"}
			}
			c.ResultUsed = vc.LowLevel.SuccessChecked
			params = sigParams(c.Signature)
			if vc.Target != nil {
				c.Declared = vc.Target.Contract
			}
		case vc.Target != nil:
			c.Declared = vc.Target.Contract
			c.Signature, c.Selector = vc.Target.Signature, vc.Target.Selector
			for _, r := range vc.Target.Returns {
				c.Returns = append(c.Returns, r.Type)
			}
			for _, p := range vc.Target.Params {
				params = append(params, p.Type)
			}
		}
		width := -1
		if len(params) > 0 {
			width = fixedLen(params[len(params)-1])
		}
		// against the verifiers in the repository it can reach
		for _, ref := range vc.Verifiers {
			c.Against = append(c.Against, compareRepo(res, ref, c))
		}
		// against what gnark exports
		backends := backendsFor(vc, res, g)
		for _, ver := range versions {
			for _, be := range backends {
				t, ok := TemplateFor(be, ver)
				if !ok {
					continue
				}
				n := width
				if n < 0 {
					n = verifierWidth(res, vc)
				}
				k := -1
				if !g.Commitments {
					k = 0
				}
				if kk := verifierCommitments(res, vc); kk >= 0 {
					k = kk
				}
				c.Against = append(c.Against, compareTemplate(t, ver, n, k, c, g.PublicCounts))
			}
		}
		c.Status = "unknown"
		if len(c.Against) > 0 {
			c.Status = "match"
			for _, a := range c.Against {
				if a.Status != "match" && a.Status != "unknown" {
					c.Status = "mismatch"
				}
			}
		}
		rep.Calls = append(rep.Calls, c)
	}
	// in-repository verifiers against the pinned template
	for _, v := range res.Verifiers {
		tc := TemplateCheck{Verifier: v.Contract, Site: fmt.Sprintf("%s:%d", v.File, v.Line), Kind: v.Kind, Template: v.Template}
		if v.Generator != solidity.GenGnark {
			tc.Status = "not-gnark"
			tc.Detail = "not generated by gnark (" + v.Generator + "): read it with the custom-verifier vector slice"
			rep.Verifiers = append(rep.Verifiers, tc)
			continue
		}
		be := strings.TrimPrefix(v.Kind, "gnark-")
		tc.Status = "unknown"
		tc.Detail = "no pinned gnark version to compare with"
		con, _ := res.ContractByName(v.Contract)
		for _, ver := range versions {
			t, ok := TemplateFor(be, ver)
			if !ok {
				continue
			}
			tc.Pinned = ver
			exp := t.Expect(v.NbPublic, boolK(v.Commitments, be))
			have := map[string]bool{}
			for _, fn := range con.Functions {
				if fn.Signature != "" {
					have[fn.Signature] = true
				}
			}
			found := false
			for _, e := range exp {
				if have[e.Signature] && !strings.Contains(e.Variant, "compressed") {
					found = true
				}
			}
			var sigs []string
			for _, e := range exp {
				if !strings.Contains(e.Variant, "compressed") {
					sigs = append(sigs, e.Signature)
				}
			}
			if found {
				tc.Status = "match"
				tc.Detail = fmt.Sprintf("its %s matches what gnark %s exports for %s", t.Function, ver, be)
			} else {
				tc.Status = "mismatch"
				var hs []string
				for _, fn := range con.Functions {
					if fn.Name == t.Function && fn.Signature != "" {
						hs = append(hs, fn.Signature)
					}
				}
				tc.Detail = fmt.Sprintf("gnark %s exports %s for %s, the contract has %s: it was not exported by the pinned version (older or newer gnark, a hand edit, or a stub); regenerate it and compare (`verifier regen`, `verifier diff`)",
					ver, strings.Join(sigs, " or "), be, orNone(hs))
			}
		}
		rep.Verifiers = append(rep.Verifiers, tc)
	}
	return rep
}

func boolK(commitments bool, backend string) int {
	if backend != "groth16" {
		return -1
	}
	if commitments {
		return 1
	}
	return 0
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "no function of that name"
	}
	return strings.Join(xs, ", ")
}

func validVersions(vs []string) []string {
	var out []string
	for _, v := range vs {
		if semver.IsValid(v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return semver.Compare(out[i], out[j]) < 0 })
	return out
}

// sigParams splits `f(a,b[2],c)` into its parameter types.
func sigParams(sig string) []string {
	i := strings.Index(sig, "(")
	if i < 0 || !strings.HasSuffix(sig, ")") {
		return nil
	}
	inner := sig[i+1 : len(sig)-1]
	if inner == "" {
		return nil
	}
	return strings.Split(inner, ",")
}

// backendsFor guesses which gnark backends a call can target: from the
// verifiers it reaches, else the callee name (Verify is the PLONK
// template's), else the backends the Go code imports.
func backendsFor(vc solidity.VerifyCall, res *solidity.Result, g Gnark) []string {
	set := map[string]bool{}
	for _, ref := range vc.Verifiers {
		for _, v := range res.Verifiers {
			if v.Contract == ref.Contract && v.Generator == solidity.GenGnark {
				set[strings.TrimPrefix(v.Kind, "gnark-")] = true
			}
		}
	}
	if len(set) == 0 {
		switch vc.Callee {
		case "Verify":
			set["plonk"] = true
		case "verifyProof", "verifyCompressedProof":
			set["groth16"] = true
		}
		if len(g.Backends) > 0 {
			for k := range set {
				if !contains(g.Backends, k) {
					delete(set, k)
				}
			}
			if len(set) == 0 && vc.Callee != "verify" && vc.Callee != "verifyTx" {
				for _, b := range g.Backends {
					set[b] = true
				}
			}
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func verifierWidth(res *solidity.Result, vc solidity.VerifyCall) int {
	for _, ref := range vc.Verifiers {
		for _, v := range res.Verifiers {
			if v.Contract == ref.Contract && v.NbPublic >= 0 {
				return v.NbPublic
			}
		}
	}
	return -1
}

func verifierCommitments(res *solidity.Result, vc solidity.VerifyCall) int {
	for _, ref := range vc.Verifiers {
		for _, v := range res.Verifiers {
			if v.Contract == ref.Contract && v.Kind == "gnark-groth16" {
				if v.Commitments {
					return 1
				}
				return 0
			}
		}
	}
	return -1
}

func compareRepo(res *solidity.Result, ref solidity.VerifierRef, c ABICheck) Comparison {
	cmp := Comparison{Against: "repo-verifier", Name: fmt.Sprintf("%s (%s:%d)", ref.Contract, ref.File, ref.Line), Returns: []string{}}
	con, ok := res.ContractByName(ref.Contract)
	if !ok || c.Signature == "" {
		cmp.Status = "unknown"
		cmp.Detail = "the call's signature or the verifier's functions could not be read"
		return cmp
	}
	var same *solidity.Function
	var named []string
	for i, fn := range con.Functions {
		if fn.Name != c.Callee {
			continue
		}
		named = append(named, fn.Signature)
		if fn.Signature == c.Signature {
			same = &con.Functions[i]
		}
	}
	if same == nil {
		cmp.Status = "selector-mismatch"
		if len(named) > 0 {
			cmp.Signature = named[0]
			cmp.Selector = keccak.Selector(named[0])
		}
		cmp.Detail = fmt.Sprintf("the caller sends %s (%s); %s has %s. No function matches the selector, so the call reverts (or reaches a fallback)",
			c.Signature, c.Selector, ref.Contract, orNone(named))
		return cmp
	}
	cmp.Signature, cmp.Selector = same.Signature, same.Selector
	for _, r := range same.Returns {
		cmp.Returns = append(cmp.Returns, r.Type)
	}
	return judgeReturns(cmp, c, cmp.Returns, "")
}

// judgeReturns compares what the caller decodes with what the verifier
// returns.
func judgeReturns(cmp Comparison, c ABICheck, returns []string, onFailure string) Comparison {
	callerBool := len(c.Returns) == 1 && c.Returns[0] == "bool"
	verBool := len(returns) == 1 && returns[0] == "bool"
	switch {
	case callerBool && len(returns) == 0:
		cmp.Status = "return-mismatch"
		cmp.Detail = "the caller decodes a bool, the verifier returns nothing (it reverts on failure): Solidity's decoder reverts on the empty return data, so every call reverts, valid proofs included"
	case !callerBool && verBool && c.Via != "staticcall" && c.Via != "call":
		cmp.Status = "return-mismatch"
		cmp.Detail = "the verifier returns a bool (false for an invalid proof) and the caller's interface declares no return value, so the result is never checked: invalid proofs pass"
	case verBool && !c.ResultUsed:
		cmp.Status = "bool-ignored"
		cmp.Detail = "the verifier returns false for an invalid proof and the caller does not check the result (V-VC3)"
	case (c.Via == "staticcall" || c.Via == "call") && verBool && !callerBool:
		cmp.Status = "bool-ignored"
		cmp.Detail = "a low-level call's success flag is true when the verifier returns false; the return data must be decoded and checked"
	case (c.Via == "staticcall" || c.Via == "call") && !c.ResultUsed:
		cmp.Status = "bool-ignored"
		cmp.Detail = "the low-level call's success flag is not checked: a reverting verifier does not stop the caller"
	default:
		cmp.Status = "match"
		cmp.Detail = "selector and return value match"
	}
	if onFailure != "" {
		cmp.OnFailure = onFailure
	}
	return cmp
}

func compareTemplate(t Template, ver string, n, k int, c ABICheck, counts []int) Comparison {
	cmp := Comparison{Against: "gnark-template", Name: fmt.Sprintf("gnark %s %s (%s)", ver, t.Backend, t.Source), Returns: t.Returns, OnFailure: t.OnFailure}
	if cmp.Returns == nil {
		cmp.Returns = []string{}
	}
	exp := t.Expect(n, k)
	if c.Signature == "" {
		cmp.Status = "unknown"
		var sigs []string
		for _, e := range exp {
			sigs = append(sigs, e.Signature)
		}
		cmp.Detail = "the caller's signature could not be read (a struct parameter or an unresolved interface); gnark exports " + strings.Join(sigs, " or ")
		return cmp
	}
	var hit *Expected
	for i, e := range exp {
		if e.Signature == c.Signature {
			hit = &exp[i]
		}
	}
	if hit == nil {
		// same shape with another width?
		for _, e := range exp {
			if strings.Contains(e.Signature, "[N]") {
				continue
			}
			if stripWidth(e.Signature) == stripWidth(c.Signature) {
				cmp.Signature, cmp.Selector = e.Signature, e.Selector
				cmp.Status = "width-mismatch"
				cmp.Detail = fmt.Sprintf("the caller passes %s, gnark %s's verifier for this circuit takes %s: the selector differs and the call reverts", c.Signature, ver, e.Signature)
				return cmp
			}
		}
		var sigs []string
		for _, e := range exp {
			s := e.Signature
			if e.Selector != "" {
				s += " (" + e.Selector + ")"
			}
			sigs = append(sigs, s)
		}
		if len(exp) > 0 {
			cmp.Signature, cmp.Selector = exp[0].Signature, exp[0].Selector
		}
		cmp.Status = "selector-mismatch"
		cmp.Detail = fmt.Sprintf("the caller sends %s (%s); gnark %s exports %s for %s. A verifier exported by the pinned gnark has no function with this selector, so the call reverts",
			c.Signature, c.Selector, ver, strings.Join(sigs, " or "), t.Backend)
		return cmp
	}
	cmp.Signature, cmp.Selector = hit.Signature, hit.Selector
	cmp = judgeReturns(cmp, c, t.Returns, t.OnFailure)
	if cmp.Status == "match" && n >= 0 && len(counts) > 0 && !containsInt(counts, n) {
		cmp.Status = "width-mismatch"
		cmp.Detail = fmt.Sprintf("the signature matches, but no production circuit has %d public inputs (circuits: %v)", n, counts)
	}
	return cmp
}

var reWidth = regexp.MustCompile(`\[\d+\]`)

func stripWidth(sig string) string {
	// only the last parameter's width (the public inputs) is free
	i := strings.LastIndex(sig, ",")
	if i < 0 {
		i = strings.Index(sig, "(")
	}
	return sig[:i] + reWidth.ReplaceAllString(sig[i:], "[]")
}

func containsInt(xs []int, x int) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
