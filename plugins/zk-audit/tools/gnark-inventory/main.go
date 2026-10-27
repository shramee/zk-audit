// Command gnark-inventory is the deterministic recon tool of the zk-audit
// plugin: stack detection, gnark circuit / witness / hint / footgun
// inventory, Solidity integration scan, ledger seeding, and validators for
// the plugin's JSON documents.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/advisory"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/kblint"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/ledger"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/report"
	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/validate"
)

// Version of the tool; keep in step with plugin.json.
const Version = "0.1.0"

const usage = `gnark-inventory ` + Version + ` — deterministic recon for zk-audit

Usage:
  gnark-inventory detect    --repo DIR [--out stack.json]
  gnark-inventory inventory --repo DIR --out DIR [--files a.go,dir/] [--syntax-only] [--allow-network]
  gnark-inventory validate  findings|ledger|stack FILE
  gnark-inventory lint-kb   SKILL_DIR
  gnark-inventory advisories [--version vX.Y.Z]
  gnark-inventory rules
  gnark-inventory version

Exit status: 0 ok, 1 validation or lint failure, 2 usage or I/O error.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "detect":
		err = cmdDetect(os.Args[2:], os.Stdout)
	case "inventory":
		err = cmdInventory(os.Args[2:], os.Stdout)
	case "validate":
		code, err = cmdValidate(os.Args[2:], os.Stdout)
	case "lint-kb":
		code, err = cmdLint(os.Args[2:], os.Stdout)
	case "advisories":
		err = cmdAdvisories(os.Args[2:], os.Stdout)
	case "rules":
		err = writeJSON(os.Stdout, inventory.Rules)
	case "version", "--version", "-v":
		fmt.Println(Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gnark-inventory:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSON(f, v)
}

func repoFlag(fs *flag.FlagSet) *string {
	return fs.String("repo", ".", "target repository root")
}

func absRepo(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(a)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", a)
	}
	return a, nil
}

func cmdDetect(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	repo := repoFlag(fs)
	out := fs.String("out", "", "write stack.json here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := absRepo(*repo)
	if err != nil {
		return err
	}
	st, err := detect.Detect(root, Version)
	if err != nil {
		return err
	}
	if *out == "" {
		return writeJSON(stdout, st)
	}
	if err := writeJSONFile(*out, st); err != nil {
		return err
	}
	fmt.Fprintln(stdout, stackLine(st))
	return nil
}

// stackLine is the one-line banner the skill prints after Phase 0.
func stackLine(st *detect.Stack) string {
	var parts []string
	if st.Gnark.Present {
		parts = append(parts, fmt.Sprintf("gnark %s (advisories: %d)", strings.Join(st.Gnark.Versions, ","), len(st.Gnark.Advisories)))
	} else {
		parts = append(parts, "gnark: no")
	}
	if len(st.Gnark.Backends) > 0 {
		parts = append(parts, strings.Join(st.Gnark.Backends, "/"))
	}
	if len(st.Gnark.Curves) > 0 {
		parts = append(parts, strings.Join(st.Gnark.Curves, ","))
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	parts = append(parts, "solidity: "+yes(st.Solidity.Present), "foundry: "+yes(st.Foundry.Present))
	if st.Circom.Present {
		parts = append(parts, "circom: yes")
	}
	if st.Noir.Present {
		parts = append(parts, "noir: yes")
	}
	return strings.Join(parts, " · ")
}

func cmdInventory(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	repo := repoFlag(fs)
	out := fs.String("out", "", "output directory (required)")
	files := fs.String("files", "", "comma-separated repo-relative files or directories to report on")
	syntax := fs.Bool("syntax-only", false, "skip go/packages type loading")
	network := fs.Bool("allow-network", false, "let the go command download modules while loading")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("inventory: --out is required")
	}
	root, err := absRepo(*repo)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if inside(*out, root) {
		fmt.Fprintln(os.Stderr, "gnark-inventory: warning: --out is inside the target repository")
	}
	var scope []string
	for _, f := range strings.Split(*files, ",") {
		if f = strings.TrimSpace(f); f != "" {
			scope = append(scope, filepath.ToSlash(f))
		}
	}
	prog, err := load.Load(root, load.Options{SyntaxOnly: *syntax, AllowNetwork: *network})
	if err != nil {
		return err
	}
	inv, err := inventory.Build(prog, inventory.Options{ToolVersion: Version, Files: scope})
	if err != nil {
		return err
	}
	st, err := detect.Detect(root, Version)
	if err != nil {
		return err
	}
	led := ledger.Seed(inv, st, "gnark-inventory "+Version)
	if err := writeJSONFile(filepath.Join(*out, "inventory.json"), inv); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "inventory.md"), []byte(report.Inventory(inv)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "binding-table.md"), []byte(report.BindingTable(inv)), 0o644); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "coverage-ledger.json"), led); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "stack.json"), st); err != nil {
		return err
	}
	s := inv.Summary
	fmt.Fprintf(stdout, "load: %s · circuits: %d · public inputs (static): %d · hint sites: %d (unreached outputs: %d) · footgun hits: %d · verify calls: %d · ledger units: %d\n",
		inv.LoadMode, s.Circuits, s.PublicInputs, s.HintSites, s.UnreachedHints, countHits(s.Footguns), s.VerifyCalls, len(led.Units))
	fmt.Fprintf(stdout, "wrote %s/{inventory.json,inventory.md,binding-table.md,coverage-ledger.json,stack.json}\n", *out)
	if len(inv.LoadErrors) > 0 {
		fmt.Fprintf(stdout, "note: %d load errors (first: %s)\n", len(inv.LoadErrors), inv.LoadErrors[0])
	}
	return nil
}

func countHits(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func inside(p, root string) bool {
	a, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, a)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func cmdValidate(args []string, stdout io.Writer) (int, error) {
	if len(args) != 2 {
		return 2, fmt.Errorf("validate: want KIND FILE")
	}
	doc, err := os.ReadFile(args[1])
	if err != nil {
		return 2, err
	}
	rep, err := validate.Document(args[0], doc)
	if err != nil {
		return 2, err
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(stdout, "error:", e)
	}
	if !rep.OK() {
		fmt.Fprintf(stdout, "FAIL %s %s: %d errors, %d items inspected\n", rep.Kind, args[1], len(rep.Errors), rep.Items)
		return 1, nil
	}
	fmt.Fprintf(stdout, "OK %s %s: %d items inspected\n", rep.Kind, args[1], rep.Items)
	return 0, nil
}

func cmdLint(args []string, stdout io.Writer) (int, error) {
	if len(args) != 1 {
		return 2, fmt.Errorf("lint-kb: want SKILL_DIR")
	}
	rep, err := kblint.Lint(args[0], inventory.RuleIDs())
	if err != nil {
		return 2, err
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(stdout, "error:", e)
	}
	fmt.Fprintf(stdout, "%s: %d vectors in %d slices, %d reference files checked\n", map[bool]string{true: "OK", false: "FAIL"}[rep.OK()], rep.Vectors, rep.Slices, rep.Files)
	if !rep.OK() {
		return 1, nil
	}
	return 0, nil
}

func cmdAdvisories(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("advisories", flag.ContinueOnError)
	ver := fs.String("version", "", "only advisories affecting this gnark version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tab, err := advisory.Load()
	if err != nil {
		return err
	}
	if *ver == "" {
		_, err := stdout.Write(advisory.Raw())
		return err
	}
	return writeJSON(stdout, tab.Affecting(*ver))
}
