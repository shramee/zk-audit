package assemble

// The types below mirror schemas/findings.schema.json and
// schemas/ledger.schema.json. Inputs are schema-validated before decoding,
// so the decoder can assume required fields are present.

// Location is a source location.
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
	Scope   string `json:"scope"`
}

// FixOption is one alternative fix.
type FixOption struct {
	Label string `json:"label"`
	Diff  string `json:"diff"`
}

// Fix is a record's fix block.
type Fix struct {
	Summary string      `json:"summary"`
	Options []FixOption `json:"options"`
}

// PoC is the result of the poc-builder.
type PoC struct {
	Path          string `json:"path"`
	Command       string `json:"command"`
	Result        string `json:"result"`
	Demonstrates  string `json:"demonstrates"`
	Package       string `json:"package"`
	OutputExcerpt string `json:"output_excerpt"`
}

// Gates are the four judging gates.
type Gates struct {
	Executes     string `json:"executes"`
	Reachable    string `json:"reachable"`
	Unprivileged string `json:"unprivileged"`
	Impact       string `json:"impact"`
}

// Refuter is the fresh refuter's verdict.
type Refuter struct {
	Verdict   string `json:"verdict"`
	Reasoning string `json:"reasoning"`
	Mechanism string `json:"mechanism"`
	Impact    string `json:"impact"`
	By        string `json:"by"`
}

// Record is one findings.json record of any verdict.
type Record struct {
	Fingerprint      string     `json:"fingerprint"`
	Verdict          string     `json:"verdict"`
	Title            string     `json:"title"`
	Layer            string     `json:"layer"`
	BugClass         string     `json:"bug_class"`
	Location         Location   `json:"location"`
	RelatedLocations []Location `json:"related_locations"`
	DetectedBy       []string   `json:"detected_by"`
	VectorIDs        []string   `json:"vector_ids"`
	Description      string     `json:"description"`
	RunTag           string     `json:"run_tag"`
	Seen             *Seen      `json:"seen"`

	Severity   string   `json:"severity"`
	Confidence *int     `json:"confidence"`
	Evidence   string   `json:"evidence"`
	Proof      string   `json:"proof"`
	Impact     string   `json:"impact"`
	Gates      *Gates   `json:"gates"`
	Fix        *Fix     `json:"fix"`
	PoC        *PoC     `json:"poc"`
	Refuter    *Refuter `json:"refuter"`
	Chain      []string `json:"chain"`

	Blockers       []string `json:"blockers"`
	ValidationPlan string   `json:"validation_plan"`

	Reason           string    `json:"reason"`
	RefutingLocation *Location `json:"refuting_location"`

	CodeSmells []string `json:"code_smells"`
	Unverified string   `json:"unverified"`

	Trust       *Trust `json:"trust"`
	Calibration string `json:"calibration"`
	Property    string `json:"property"`
}

// Trust is a trusted-party record's trust object.
type Trust struct {
	Party      string   `json:"party"`
	Role       string   `json:"role"`
	Power      string   `json:"power"`
	Breaks     []string `json:"breaks"`
	Assumption string   `json:"assumption"`
	Mitigation string   `json:"mitigation"`
	Accepted   bool     `json:"accepted"`
	Source     string   `json:"source"`
	LeadReason string   `json:"lead_reason"`
}

// AcceptedRisk is a risk zk-audit.md accepts that no record covers.
type AcceptedRisk struct {
	Party  string `json:"party"`
	Risk   string `json:"risk"`
	Source string `json:"source"`
}

// Seen is loop mode's "seen in k of N passes".
type Seen struct {
	Passes int `json:"passes"`
	Of     int `json:"of"`
}

// Hardening is one hygiene note.
type Hardening struct {
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Location *Location `json:"location"`
}

// Companions records which companion skills were present.
type Companions struct {
	Present []string `json:"present"`
	Missing []string `json:"missing"`
}

// Findings is findings.json.
type Findings struct {
	Repo             string      `json:"repo"`
	Commit           string      `json:"commit"`
	RunID            string      `json:"run_id"`
	Profile          string      `json:"profile"`
	NoFindings       bool        `json:"no_findings"`
	NoFindingsReason string      `json:"no_findings_reason"`
	Posture          string      `json:"posture"`
	OutOfScope       []string    `json:"out_of_scope"`
	Companions       *Companions `json:"companions"`
	Hardening        []Hardening    `json:"hardening"`
	AcceptedRisks    []AcceptedRisk `json:"accepted_risks"`
	Records          []Record       `json:"records"`
}

// Unit is one coverage-ledger unit.
type Unit struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Subject            string   `json:"subject"`
	Class              string   `json:"class"`
	Paths              []string `json:"paths"`
	Status             string   `json:"status"`
	AgentIDs           []string `json:"agent_ids"`
	ReviewedPaths      []string `json:"reviewed_paths"`
	ResultFingerprints []string `json:"result_fingerprints"`
	Reason             string   `json:"reason"`
}

// Ledger is coverage-ledger.json.
type Ledger struct {
	Repo    string `json:"repo"`
	RunID   string `json:"run_id"`
	Profile string `json:"profile"`
	Units   []Unit `json:"units"`
}

// Inventory holds the parts of inventory.json the report uses.
type Inventory struct {
	LoadMode   string   `json:"load_mode"`
	LoadErrors []string `json:"load_errors"`
}
