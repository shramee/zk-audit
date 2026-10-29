// Package detect produces stack.json: which ZK stack a repository uses, which
// gnark version it pins and which advisories match that version.
package detect

import (
	"go/parser"
	"go/token"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/advisory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/gomod"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

// SchemaVersion of stack.json.
const SchemaVersion = "1"

const (
	gnarkModule       = "github.com/consensys/gnark"
	gnarkCryptoModule = "github.com/consensys/gnark-crypto"
)

// Module is one go.mod in the repository.
type Module struct {
	Path        string `json:"path"`
	Module      string `json:"module"`
	Go          string `json:"go,omitempty"`
	Toolchain   string `json:"toolchain,omitempty"`
	Gnark       string `json:"gnark,omitempty"`
	GnarkLocal  string `json:"gnark_replaced_by,omitempty"`
	GnarkCrypto string `json:"gnark_crypto,omitempty"`
}

// AdvisoryHit is an advisory matched against a module's gnark version.
type AdvisoryHit struct {
	advisory.Match
	Module  string `json:"module"`
	Version string `json:"version"`
}

// Gnark summarises gnark usage.
type Gnark struct {
	Present    bool          `json:"present"`
	Versions   []string      `json:"versions"`
	Advisories []AdvisoryHit `json:"advisories"`
	// AdvisoryTableAsOf is the date of the embedded advisory table.
	AdvisoryTableAsOf string   `json:"advisory_table_as_of,omitempty"`
	Backends          []string `json:"backends"`
	Builders          []string `json:"builders"`
	Curves            []string `json:"curves"`
	Features          []string `json:"features"`
}

// Presence of a non-Go stack component.
type Presence struct {
	Present bool     `json:"present"`
	Files   int      `json:"files"`
	Paths   []string `json:"paths,omitempty"`
}

// Stack is the stack.json document.
type Stack struct {
	SchemaVersion string       `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	Repo          string       `json:"repo"`
	GoModules     []Module     `json:"go_modules"`
	Gnark         Gnark        `json:"gnark"`
	Solidity      SolidityInfo `json:"solidity"`
	Foundry       Presence     `json:"foundry"`
	Hardhat       Presence     `json:"hardhat"`
	Circom        Presence     `json:"circom"`
	Noir          Presence     `json:"noir"`
	// Library describes exported gnark gadgets; Mode is true when the
	// repository looks like a gadget library (library mode).
	Library   Library        `json:"library"`
	Routes    []string       `json:"routes"`
	Notes     []string       `json:"notes"`
	Languages map[string]int `json:"languages"`
}

// Library summarises exported gnark gadgets: exported functions and
// methods outside test files and package main that take a frontend.API or
// an *emulated.Field. Mode is true when there are gadgets but no
// production circuit (a non-test Define) and no verifier contract.
type Library struct {
	Mode               bool     `json:"mode"`
	Gadgets            int      `json:"gadgets"`
	Packages           []string `json:"packages"`
	ProductionCircuits int      `json:"production_circuits"`
	Reason             string   `json:"reason"`
}

// SolidityInfo describes Solidity sources and verifier contracts.
type SolidityInfo struct {
	Present   bool                `json:"present"`
	Files     int                 `json:"files"`
	Verifiers []solidity.Verifier `json:"verifiers"`
}

var (
	reCurve = regexp.MustCompile(`\becc\.(BN254|BLS12_381|BLS12_377|BW6_761|BW6_633|BLS24_315|BLS24_317|STARK_CURVE|SECP256K1|GRUMPKIN)\b`)
)

// Detect inspects root.
func Detect(root, toolVersion string) (*Stack, error) {
	st := &Stack{
		SchemaVersion: SchemaVersion, ToolVersion: toolVersion, Repo: root,
		GoModules: []Module{}, Routes: []string{}, Notes: []string{}, Languages: map[string]int{},
		Gnark:    Gnark{Versions: []string{}, Advisories: []AdvisoryHit{}, Backends: []string{}, Builders: []string{}, Curves: []string{}, Features: []string{}},
		Solidity: SolidityInfo{Verifiers: []solidity.Verifier{}},
		Library:  Library{Packages: []string{}},
	}
	tab, err := advisory.Load()
	if err != nil {
		return nil, err
	}
	st.Gnark.AdvisoryTableAsOf = tab.AsOf
	files, err := fsutil.Walk(root, nil)
	if err != nil {
		return nil, err
	}
	backends, builders, curves, features := set{}, set{}, set{}, set{}
	versions := set{}
	var sols []fsutil.File
	hasMod := false
	for _, f := range files {
		if path.Base(f.Rel) == "go.mod" {
			hasMod = true
		}
	}
	if !hasMod {
		// a package directory inside a module (for example a gnark std
		// package in the module cache): read the enclosing go.mod
		if abs, rel := gomod.Enclosing(root); abs != "" {
			files = append([]fsutil.File{{Abs: abs, Rel: rel}}, files...)
		}
	}
	lib := &libScan{pkgs: set{}}
	for _, f := range files {
		base := path.Base(f.Rel)
		ext := path.Ext(f.Rel)
		switch {
		case base == "go.mod":
			m, err := gomod.ParseFile(f.Abs)
			if err != nil {
				st.Notes = append(st.Notes, f.Rel+": "+err.Error())
				continue
			}
			mod := Module{Path: f.Rel, Module: m.Module, Go: m.Go, Toolchain: m.Toolchain}
			if m.Module == gnarkModule {
				// gnark itself: the version is the module cache directory's
				// (gnark@vX.Y.Z), else unknown
				v := selfVersion(f.Abs)
				mod.Gnark = v
				st.Gnark.Present = true
				key := v
				if key == "" {
					key = "(gnark itself)"
				}
				if !versions[key] {
					versions[key] = true
					st.Gnark.Versions = append(st.Gnark.Versions, key)
				}
				if v != "" {
					for _, hit := range tab.Affecting(v) {
						st.Gnark.Advisories = append(st.Gnark.Advisories, AdvisoryHit{Match: hit, Module: f.Rel, Version: v})
					}
				} else {
					st.Notes = append(st.Notes, f.Rel+": this repository is gnark itself at an unknown version; advisories are not matched")
				}
			}
			if v, by, ok := m.Version(gnarkModule); ok {
				mod.Gnark, mod.GnarkLocal = v, by
				st.Gnark.Present = true
				key := v
				if key == "" {
					key = "(replaced by " + by + ")"
				}
				if !versions[key] {
					versions[key] = true
					st.Gnark.Versions = append(st.Gnark.Versions, key)
				}
				for _, hit := range tab.Affecting(v) {
					st.Gnark.Advisories = append(st.Gnark.Advisories, AdvisoryHit{Match: hit, Module: f.Rel, Version: key})
				}
			}
			if v, _, ok := m.Version(gnarkCryptoModule); ok {
				mod.GnarkCrypto = v
				if v != "" {
					for _, hit := range tab.AffectingModule(advisory.GnarkCrypto, v) {
						st.Gnark.Advisories = append(st.Gnark.Advisories, AdvisoryHit{Match: hit, Module: f.Rel, Version: v})
					}
				}
			}
			st.GoModules = append(st.GoModules, mod)
		case base == "foundry.toml":
			st.Foundry.Present = true
			st.Foundry.Files++
			st.Foundry.Paths = append(st.Foundry.Paths, f.Rel)
		case strings.HasPrefix(base, "hardhat.config."):
			st.Hardhat.Present = true
			st.Hardhat.Files++
			st.Hardhat.Paths = append(st.Hardhat.Paths, f.Rel)
		case base == "Nargo.toml":
			st.Noir.Present = true
			st.Noir.Paths = append(st.Noir.Paths, f.Rel)
		case ext == ".nr":
			st.Noir.Files++
			st.Languages["noir"]++
		case ext == ".circom":
			st.Circom.Present = true
			st.Circom.Files++
			st.Languages["circom"]++
		case ext == ".sol":
			st.Languages["solidity"]++
			sols = append(sols, f)
		case ext == ".go":
			st.Languages["go"]++
			scanGo(f, backends, builders, curves, features, lib)
		}
	}
	st.Library.Gadgets, st.Library.ProductionCircuits, st.Library.Packages = lib.gadgets, lib.circuits, lib.pkgs.sorted()
	st.Gnark.Backends = backends.sorted()
	st.Gnark.Builders = builders.sorted()
	st.Gnark.Curves = curves.sorted()
	st.Gnark.Features = features.sorted()
	if len(sols) > 0 {
		st.Solidity.Present = true
		st.Solidity.Files = len(sols)
		res, err := solidity.ScanFiles(sols)
		if err != nil {
			return nil, err
		}
		st.Solidity.Verifiers = res.Verifiers
	}
	if len(st.Circom.Paths) == 0 && st.Circom.Files > 0 {
		st.Circom.Paths = nil
	}
	st.library()
	st.routes()
	return st, nil
}

type set map[string]bool

func (s set) sorted() []string {
	out := []string{}
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scanGo(f fsutil.File, backends, builders, curves, features set, lib *libScan) {
	src, err := os.ReadFile(f.Abs)
	if err != nil {
		return
	}
	af, err := parser.ParseFile(token.NewFileSet(), f.Abs, src, parser.ImportsOnly)
	if err != nil || af == nil {
		return
	}
	lib.scan(f, src, af)
	gnark := false
	for _, imp := range af.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if p == gnarkModule || strings.HasPrefix(p, gnarkModule+"/") {
			gnark = true
		}
		switch {
		case strings.HasPrefix(p, gnarkModule+"/backend/groth16"):
			backends["groth16"] = true
		case strings.HasPrefix(p, gnarkModule+"/backend/plonk"):
			backends["plonk"] = true
		case p == gnarkModule+"/frontend/cs/r1cs":
			builders["r1cs"] = true
		case p == gnarkModule+"/frontend/cs/scs":
			builders["scs"] = true
		case p == gnarkModule+"/test/unsafekzg":
			if !strings.HasSuffix(f.Rel, "_test.go") {
				features["unsafekzg-outside-tests"] = true
			}
		case strings.HasPrefix(p, gnarkModule+"/std/recursion"):
			features["recursion"] = true
		case p == gnarkModule+"/std/multicommit":
			features["multicommit"] = true
		case p == gnarkModule+"/backend/solidity":
			features["solidity-options"] = true
		case strings.HasPrefix(p, gnarkModule+"/std/math/emulated"):
			features["emulated-arithmetic"] = true
		case strings.HasPrefix(p, gnarkModule+"/std/signature"):
			features["signatures"] = true
		case strings.HasPrefix(p, gnarkModule+"/std/evmprecompiles"):
			features["evm-precompiles"] = true
		}
	}
	if !gnark {
		return
	}
	text := string(src)
	for _, m := range reCurve.FindAllStringSubmatch(text, -1) {
		curves[strings.ToLower(m[1])] = true
	}
	if strings.Contains(text, "ExportSolidity(") {
		features["export-solidity"] = true
	}
	if strings.Contains(text, "WithProverTargetSolidityVerifier") {
		features["prover-target-solidity"] = true
	}
	if strings.Contains(text, "frontend.Committer") || strings.Contains(text, "multicommit.WithCommitment") {
		features["commitments"] = true
	}
}

func (st *Stack) routes() {
	if st.Gnark.Present {
		st.Routes = append(st.Routes, "gnark: native zk-audit engine")
	}
	if st.Library.Mode {
		st.Routes = append(st.Routes, "gnark gadget library: library mode (profile library): gadget inventory, doc-contract lens L1, per-gadget PoC harness, differential tests")
	}
	if st.Solidity.Present {
		st.Routes = append(st.Routes, "solidity: integration lenses I1-I3, contract review S1 and V-contract (standard, deep), V-custom for verifiers gnark did not generate; the solidity-auditor companion runs too if installed")
	}
	if st.Circom.Present {
		st.Routes = append(st.Routes, "circom: delegate to circom-auditor if installed, else generic-zk vectors")
	}
	if st.Noir.Present {
		st.Routes = append(st.Routes, "noir: out of scope for v1; report says so")
	}
	if !st.Gnark.Present && !st.Solidity.Present {
		st.Notes = append(st.Notes, "no gnark module and no Solidity found: zk-audit does not fit this repository")
	}
	has := func(x string) bool {
		for _, f := range st.Gnark.Features {
			if f == x {
				return true
			}
		}
		return false
	}
	hasBackend := func(x string) bool {
		for _, b := range st.Gnark.Backends {
			if b == x {
				return true
			}
		}
		return false
	}
	if has("commitments") && hasBackend("groth16") {
		st.Notes = append(st.Notes, "in-circuit commitments with the Groth16 backend: check CVE-2024-45039 / CVE-2024-45040 status and commitment-to-secret privacy")
		if has("export-solidity") && !has("prover-target-solidity") {
			st.Notes = append(st.Notes, "commitments + ExportSolidity without WithProverTargetSolidityVerifier: proofs may not verify on-chain or may use a mismatched hash-to-field")
		}
	}
	if has("unsafekzg-outside-tests") {
		st.Notes = append(st.Notes, "test/unsafekzg imported outside _test.go files")
	}
	if len(st.Gnark.Versions) > 1 {
		st.Notes = append(st.Notes, "more than one gnark version pinned across modules: prover and key-generation code may disagree")
	}
	for _, m := range st.GoModules {
		if m.GnarkLocal != "" {
			st.Notes = append(st.Notes, m.Path+": gnark is replaced by "+m.GnarkLocal+"; the advisory match is by version only")
		}
	}
}
