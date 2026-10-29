// Command gnark-inventory is the deterministic recon tool of the zk-audit
// plugin: stack detection, gnark circuit / witness / hint / footgun
// inventory, Solidity integration scan, ledger seeding, and validators for
// the plugin's JSON documents.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/advisory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/assemble"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/bundle"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/kblint"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/ledger"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
	profiles "github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/report"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/sandbox"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// Version of the tool; keep in step with plugin.json and the skill VERSION file
// (TestPluginMetadata checks all three).
const Version = "0.1.0"

const usage = `gnark-inventory ` + Version + ` — deterministic recon for zk-audit

Usage:
  gnark-inventory args      [--repo DIR] [--mode M] [--run-id ID] [--home DIR] -- WORDS...
  gnark-inventory detect    --repo DIR [--out stack.json]
  gnark-inventory inventory --repo DIR --out DIR [--files a.go,dir/] [--syntax-only] [--allow-network]
  gnark-inventory bundle    --out DIR --skill SKILL_DIR [--profile P]
  gnark-inventory profiles  [--profile P] [--markdown] [--check-docs SKILL_DIR] [--sync-docs SKILL_DIR]
  gnark-inventory validate  findings|ledger|stack FILE [--out DIR]
  gnark-inventory assemble  --out DIR [--findings F] [--ledger F] [--stack F] [--inventory F] [--repo DIR] [--report F] [--file-output]
  gnark-inventory diff      --repo DIR --base REV [--head REV] [--out DIR]
  gnark-inventory ledger    mark --out DIR (--unit ID|--match S|--lens L|--kind K|--class C)... [--from STATUS] [--status S] [--agent A]... [--reviewed P]... [--fingerprint F]... [--reason R] [--notes T] [--wave N]
  gnark-inventory ledger    add  --out DIR --kind K --subject S --class C --lens L [--path FILE:LINE] [--notes T]
  gnark-inventory ledger    show --out DIR
  gnark-inventory agents    save --out DIR --id ID [--from FILE] [--status done|blocked|failed|refused] [--reason R]
  gnark-inventory agents    list --out DIR
  gnark-inventory sandbox   [--rw DIR]... [--ro DIR]... [--cwd DIR] [--timeout SEC] [--mem MB] [--allow-network] [--engine E] [--require] [--check] -- CMD [ARGS...]
  gnark-inventory lint-kb   [--gnark-src DIR] SKILL_DIR
  gnark-inventory advisories [--version vX.Y.Z]
  gnark-inventory rules
  gnark-inventory version

Exit status: 0 ok, 1 validation or lint failure, 2 usage or I/O error;
sandbox returns the command's status, 124 on the time limit, 125 when the
sandbox cannot be set up, 127 when the command does not exist.
`

func main() {
	sandbox.Stage2() // inside a sandbox: set limits and exec the command
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errUnknown marks an unknown subcommand.
var errUnknown = errors.New("unknown subcommand")

// run dispatches one subcommand and returns the exit status.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "detect":
		err = cmdDetect(args[1:], stdout)
	case "inventory":
		err = cmdInventory(args[1:], stdout)
	case "assemble":
		code, err = cmdAssemble(args[1:], stdout)
	case "bundle":
		err = cmdBundle(args[1:], stdout)
	case "validate":
		code, err = cmdValidate(args[1:], stdout)
	case "lint-kb":
		code, err = cmdLint(args[1:], stdout)
	case "advisories":
		err = cmdAdvisories(args[1:], stdout)
	case "args":
		code, err = cmdArgs(args[1:], stdout)
	case "diff":
		err = cmdDiff(args[1:], stdout)
	case "ledger":
		code, err = cmdLedger(args[1:], stdout)
	case "agents":
		code, err = cmdAgents(args[1:], stdout, os.Stdin)
	case "sandbox":
		code, err = cmdSandbox(args[1:], stdout, stderr)
	case "profiles":
		code, err = cmdProfiles(args[1:], stdout)
	case "rules":
		err = writeJSON(stdout, inventory.Rules)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, Version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "%v %q\n\n%s", errUnknown, args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "gnark-inventory:", err)
		return 2
	}
	return code
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
	if err := refuseInRepo("detect --out", *out, root); err != nil {
		return err
	}
	if err := writeJSONFile(*out, st); err != nil {
		return err
	}
	fmt.Fprintln(stdout, st.Line())
	return nil
}

func cmdInventory(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	repo := repoFlag(fs)
	out := fs.String("out", "", "output directory (required)")
	files := fs.String("files", "", "comma-separated repo-relative files or directories to report on")
	syntax := fs.Bool("syntax-only", false, "skip go/packages type loading")
	network := fs.Bool("allow-network", false, "let the go command download modules while loading")
	sb := fs.String("sandbox", "auto", "run type loading (go list) in the OS sandbox: auto (when available), on (required) or off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *sb {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("inventory: --sandbox wants auto, on or off, got %q", *sb)
	}
	if *out == "" {
		return fmt.Errorf("inventory: --out is required")
	}
	root, err := absRepo(*repo)
	if err != nil {
		return err
	}
	if err := refuseInRepo("inventory --out", *out, root); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if !*syntax && *sb != "off" && os.Getenv(sandbox.MarkerEnv) == "" {
		absOut, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		inner := []string{"--repo", root, "--out", absOut, "--files", *files}
		if *network {
			inner = append(inner, "--allow-network")
		}
		done, err := inventoryInSandbox(inner, root, absOut, *network, *sb == "on", stdout)
		if done || err != nil {
			return err
		}
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
		if missingModules(inv.LoadErrors) {
			fmt.Fprintf(stdout, "note: the target's Go modules (gnark %s) are not in the module cache, so loading fell back to syntax mode and gnark std source is unavailable to agents; with the user's consent, run `go mod download` in the target or rerun with --allow-network\n", strings.Join(st.Gnark.Versions, ","))
		}
	}
	return nil
}

// inventoryInSandbox reruns this inventory command inside the OS sandbox
// (repository read-only, only the output directory and the sandbox build
// cache writable, no network unless --allow-network), the same environment
// PoCs run in. It reports done=false when no OS sandbox exists and the caller
// should load in-process (auto mode).
func inventoryInSandbox(args []string, root, out string, network, require bool, stdout io.Writer) (bool, error) {
	eng, err := sandbox.Detect("auto")
	if err != nil {
		return true, err
	}
	if eng.Name == sandbox.None {
		if require {
			return true, fmt.Errorf("inventory: --sandbox on, but no OS sandbox is usable: %s", eng.Reason)
		}
		fmt.Fprintf(os.Stderr, "gnark-inventory: warning: no OS sandbox (%s); loading the target in-process with a hardened go environment\n", eng.Reason)
		return false, nil
	}
	self, err := os.Executable()
	if err != nil {
		return true, err
	}
	code, _, err := sandbox.Run(append([]string{self, "inventory"}, args...), sandbox.Options{
		RW: []string{out}, RO: []string{root}, Cwd: out, Network: network, Require: true,
		Env: []string{"ZK_AUDIT_SELF_EXEC=1"}, Stdout: stdout, Stderr: os.Stderr,
	})
	if err != nil {
		return true, err
	}
	if code != 0 {
		return true, fmt.Errorf("inventory: the sandboxed run exited with status %d", code)
	}
	return true, nil
}

// missingModules reports whether load errors look like an empty module cache
// (go/packages reports `invalid package name: ""` for unresolvable imports
// under GOPROXY=off).
func missingModules(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(e, `invalid package name: ""`) || strings.Contains(e, "cannot find module providing package") ||
			strings.Contains(e, "module lookup disabled by GOPROXY=off") {
			return true
		}
	}
	return false
}

func countHits(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// refuseInRepo fails when path (resolved through symlinks) lies inside the
// audited repository: the tool never writes there (SKILL.md hard rules 1
// and 2). The only exception is the report copy of assemble --file-output.
func refuseInRepo(what, path, repo string) error {
	if repo != "" && fsutil.Inside(path, repo) {
		return fmt.Errorf("%s %s is inside the audited repository %s; write outside it (only assemble --file-output may put the report copy there)", what, path, repo)
	}
	return nil
}

func cmdBundle(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory holding inventory.json (required)")
	skill := fs.String("skill", "", "zk-audit skill directory, the one holding SKILL.md (required)")
	profile := fs.String("profile", profiles.Load().Default().ID, "profile id (gnark-inventory profiles lists them)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *skill == "" {
		return fmt.Errorf("bundle: --out and --skill are required")
	}
	res, err := bundle.Build(bundle.Options{Out: *out, Skill: *skill, Profile: *profile})
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "| Agent | Shard | Bundle | Lines | Source files | Status |")
	fmt.Fprintln(stdout, "|---|---|---|---|---|---|")
	written := 0
	for _, r := range res {
		if r.Status == "written" {
			written++
			fmt.Fprintf(stdout, "| %s | %s | %s | %d | %d | written |\n", r.Agent, r.Shard, r.Path, r.Lines, r.Files)
		} else {
			fmt.Fprintf(stdout, "| %s | %s | – | – | – | skipped: %s |\n", r.Agent, r.Shard, r.Reason)
		}
	}
	if written == 0 {
		return fmt.Errorf("bundle: no bundle written (empty shards for profile %s)", *profile)
	}
	return writeJSONFile(filepath.Join(*out, "bundles", "index.json"), res)
}

// cmdValidate checks one document. Flags may come before KIND or after
// FILE: `validate findings F --out DIR`.
func cmdValidate(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory: check poc.path files under <out>/pocs/ and agent outputs under <out>/agents/")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	pos := fs.Args()
	if len(pos) > 2 {
		if err := fs.Parse(pos[2:]); err != nil {
			return 2, err
		}
		pos = append(pos[:2:2], fs.Args()...)
	}
	if len(pos) != 2 {
		return 2, fmt.Errorf("validate: want [--out DIR] KIND FILE")
	}
	args = pos
	doc, err := os.ReadFile(args[1])
	if err != nil {
		return 2, err
	}
	rep, err := validate.DocumentWith(args[0], doc, validate.Options{Out: *out})
	if err != nil {
		return 2, err
	}
	for _, i := range rep.Info {
		fmt.Fprintln(stdout, "info:", i)
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

// cmdAssemble renders REPORT.md. Exit 1 means the inputs failed validation
// and no report was written.
func cmdAssemble(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required); the other paths default to files in it")
	findings := fs.String("findings", "", "findings.json (default <out>/findings.json)")
	ledgerPath := fs.String("ledger", "", "coverage-ledger.json (default <out>/coverage-ledger.json)")
	stack := fs.String("stack", "", "stack.json (default <out>/stack.json when present)")
	inv := fs.String("inventory", "", "inventory.json (default <out>/inventory.json when present)")
	repo := fs.String("repo", "", "audited source tree for verbatim constraint quotes (default: stack.json repo)")
	reportPath := fs.String("report", "", "where to write the report (default <out>/REPORT.md)")
	fileOutput := fs.Bool("file-output", false, "also write the report to <repo>/zk-audit-report-<run-id>.md (the user asked for --file-output)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("assemble: --out is required")
	}
	def := func(v *string, name string, optional bool) {
		if *v != "" {
			return
		}
		p := filepath.Join(*out, name)
		if optional {
			if _, err := os.Stat(p); err != nil {
				return
			}
		}
		*v = p
	}
	def(findings, "findings.json", false)
	def(ledgerPath, "coverage-ledger.json", false)
	def(stack, "stack.json", true)
	def(inv, "inventory.json", true)
	def(reportPath, "REPORT.md", false)
	res, err := assemble.Assemble(assemble.Options{Out: *out, Findings: *findings, Ledger: *ledgerPath, Stack: *stack, Inventory: *inv, Repo: *repo})
	if err != nil {
		var ie *assemble.InvalidError
		if errors.As(err, &ie) {
			for _, p := range ie.Problems {
				fmt.Fprintln(stdout, "error:", p)
			}
			fmt.Fprintf(stdout, "FAIL assemble: %d problems; REPORT.md not written. Fix the inputs and rerun.\n", len(ie.Problems))
			return 1, nil
		}
		return 2, err
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for what, p := range map[string]string{"assemble --out": *out, "assemble --report": *reportPath} {
		if err := refuseInRepo(what, p, res.Repo); err != nil {
			return 2, err
		}
	}
	var copyPath string
	if *fileOutput {
		if res.Repo == "" {
			return 2, fmt.Errorf("assemble --file-output needs the audited repository (--repo or stack.json)")
		}
		copyPath = filepath.Join(res.Repo, "zk-audit-report-"+res.RunID+".md")
	}
	if err := os.WriteFile(*reportPath, []byte(res.Report), 0o644); err != nil {
		return 2, err
	}
	if res.Manifest != nil {
		if err := os.MkdirAll(filepath.Join(*out, "pocs"), 0o755); err != nil {
			return 2, err
		}
		if err := os.WriteFile(filepath.Join(*out, "pocs", "MANIFEST.json"), res.Manifest, 0o644); err != nil {
			return 2, err
		}
	}
	fmt.Fprintf(stdout, "wrote %s: %s\n", *reportPath, res.Summary)
	if copyPath != "" {
		if err := os.WriteFile(copyPath, []byte(res.Report), 0o644); err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "wrote the report copy %s (--file-output)\n", copyPath)
	}
	return 0, nil
}

func cmdLint(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("lint-kb", flag.ContinueOnError)
	gnarkSrc := fs.String("gnark-src", "", "gnark checkout; verify every cited gnark/<path> exists")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() != 1 {
		return 2, fmt.Errorf("lint-kb: want [--gnark-src DIR] SKILL_DIR")
	}
	rep, err := kblint.Lint(fs.Arg(0), inventory.RuleIDs(), kblint.Options{GnarkSrc: *gnarkSrc})
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
