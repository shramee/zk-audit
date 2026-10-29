// Package inventory finds gnark circuits, their public-witness layout, hint
// call sites and footgun hits in a loaded program.
package inventory

import (
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

// Pos is a source position.
type Pos struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Inventory is the document written to inventory.json.
type Inventory struct {
	SchemaVersion string           `json:"schema_version"`
	ToolVersion   string           `json:"tool_version"`
	Repo          string           `json:"repo"`
	LoadMode      string           `json:"load_mode"`
	LoadErrors    []string         `json:"load_errors"`
	Scope         []string         `json:"scope,omitempty"`
	Circuits      []*Circuit       `json:"circuits"`
	Hints         []*HintSite      `json:"hints"`
	HintFuncs     []*HintFunc      `json:"hint_functions"`
	Footguns      []*Footgun       `json:"footguns"`
	Contracts     *solidity.Result `json:"contracts"`
	Summary       Summary          `json:"summary"`
}

// Summary holds counts for quick display and for the ledger seed.
type Summary struct {
	GoFiles        int            `json:"go_files"`
	GnarkFiles     int            `json:"gnark_files"`
	Circuits       int            `json:"circuits"`
	PublicInputs   int            `json:"public_inputs_static"`
	HintSites      int            `json:"hint_sites"`
	UnreachedHints int            `json:"unreached_hint_outputs"`
	Footguns       map[string]int `json:"footguns_by_id"`
	SolidityFiles  int            `json:"solidity_files"`
	VerifyCalls    int            `json:"verify_calls"`
}

// Circuit is a type with a `Define(frontend.API) error` method.
type Circuit struct {
	Name        string   `json:"name"`
	Package     string   `json:"package"`
	Decl        Pos      `json:"decl"`
	Define      Pos      `json:"define"`
	InTest      bool     `json:"in_test_file"`
	PointerRecv bool     `json:"pointer_receiver"`
	Witness     *Witness `json:"witness"`
	HintIDs     []string `json:"hint_ids"`
	FootgunIDs  []string `json:"footgun_refs"`
}

// Witness is the circuit's witness layout in gnark walk order.
type Witness struct {
	// Resolved is false when some field type could not be resolved; the
	// layout is then incomplete from the first unresolved group on.
	Resolved bool `json:"resolved"`
	// Source is "types" or "syntax".
	Source string     `json:"source"`
	Public []*Group   `json:"public"`
	Secret []*Group   `json:"secret"`
	Omit   []*Omitted `json:"omitted"`
	// NbPublic / NbSecret are static counts, or -1 when a dynamic-length
	// group (slice) makes the count depend on the assignment.
	NbPublic int      `json:"nb_public"`
	NbSecret int      `json:"nb_secret"`
	Notes    []string `json:"notes"`
	// VKAt lists fields whose type is a recursion VerifyingKey.
	VKAt []Pos `json:"verifying_key_fields,omitempty"`
}

// Group is a run of consecutive witness leaves.
type Group struct {
	// Name is the gnark leaf name (path joined by '_'); "{i}" marks a
	// dynamic index.
	Name string `json:"name"`
	// GoPath is the Go selector path from the circuit value, e.g. Sig.R.X.
	GoPath string `json:"go_path"`
	Type   string `json:"type"`
	// Kind: variable, array, slice, opaque.
	Kind string `json:"kind"`
	// Len is the number of leaves, or -1 when dynamic.
	Len int `json:"len"`
	// PerElem is the static leaf count of one element of a slice of
	// structs (0 when not applicable).
	PerElem int `json:"per_element,omitempty"`
	// Start is the index of the first leaf in its visibility vector, or -1
	// when it follows a dynamic group. StartExpr is then symbolic.
	Start     int    `json:"start"`
	StartExpr string `json:"start_expr"`
	Decl      Pos    `json:"decl"`
	Note      string `json:"note,omitempty"`
}

// Omitted is a field skipped by `gnark:"-"`.
type Omitted struct {
	GoPath string `json:"go_path"`
	Type   string `json:"type"`
	Decl   Pos    `json:"decl"`
}

// HintSite is one NewHint call.
type HintSite struct {
	ID        string        `json:"id"`
	Pos       Pos           `json:"pos"`
	Function  string        `json:"function"`
	Circuit   string        `json:"circuit,omitempty"`
	Call      string        `json:"call"`
	HintFunc  string        `json:"hint_func"`
	HintDecl  *Pos          `json:"hint_decl,omitempty"`
	OutVar    string        `json:"out_var,omitempty"`
	NbOutputs string        `json:"nb_outputs"`
	Outputs   []*HintOutput `json:"outputs"`
	// Status: reached, partially_unreached, unreached, escapes.
	Status string `json:"status"`
	InTest bool   `json:"in_test_file"`
}

// HintOutput is the reachability verdict for one output (or all outputs,
// Index "*", when they are only used as a slice).
type HintOutput struct {
	Index     string   `json:"index"`
	Status    string   `json:"status"`
	ReachedBy []string `json:"reached_by,omitempty"`
	Escapes   []string `json:"escapes,omitempty"`
}

// HintFunc is a function with the solver.Hint signature.
type HintFunc struct {
	Name       string `json:"name"`
	Pos        Pos    `json:"pos"`
	Registered bool   `json:"registered"`
	CallSites  int    `json:"call_sites"`
}

// Footgun is one hit of a detector in footgunRules.
type Footgun struct {
	// Key is unique per hit (F1, F2, ...); ID is the rule id.
	Key      string `json:"key"`
	ID       string `json:"id"`
	Pos      Pos    `json:"pos"`
	Function string `json:"function,omitempty"`
	Circuit  string `json:"circuit,omitempty"`
	Snippet  string `json:"snippet"`
	Note     string `json:"note"`
	InTest   bool   `json:"in_test_file"`
}
