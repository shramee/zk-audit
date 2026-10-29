package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/detect"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/verifier"
)

const verifierUsage = `gnark-inventory verifier: verifier provenance checks

  verifier abi       --repo DIR [--gnark vX.Y.Z] [--backend groth16|plonk] [--json]
      Compare every verification call's interface (selector, return value,
      input width) with the verifiers in the repository and with the verifier
      the pinned gnark version exports. Exit 1 when a mismatch is found.
  verifier diff      --a FILE --b FILE [--json]
      Compare two verifier sources: structure (template, functions,
      public inputs, commitments, template constants, code with VK values
      masked) and, separately, the verifying-key constants.
  verifier vk        --sol FILE [--json]
      List the verifying-key constants of a verifier source.
  verifier bytecode  (--deployed FILE | --rpc URL --address 0x...) [--block B] [--local FILE] [--sol FILE] [--json]
      Compare deployed runtime bytecode (a hex file, or fetched with
      eth_getCode: network, only when the user asked for it) with a local
      build (hex or a forge artifact JSON; metadata stripped, immutables
      masked), and look for the source's VK constants among the deployed
      code's PUSH immediates.
  verifier regen     --repo DIR --out DIR (--main PKGDIR | --vk FILE | --circuit PKGDIR.Type) [--backend groth16|plonk] [--compare FILE] [--sandbox auto|on|off]
      Regenerate the verifier with the target's own gnark, in the sandbox,
      in a copy of the repository under <out>/regen; --compare diffs the
      result with a committed verifier.
  verifier ceremony  --repo DIR [--json]
      List key-generation calls (single-party Setup, unsafe SRS, mpcsetup)
      and key or ceremony files, with contribution counts where the format
      records them.
`

func cmdVerifier(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, verifierUsage)
		if len(args) == 0 {
			return 2, nil
		}
		return 0, nil
	}
	switch args[0] {
	case "abi":
		return verifierABI(args[1:], stdout)
	case "diff":
		return verifierDiff(args[1:], stdout)
	case "vk":
		return verifierVK(args[1:], stdout)
	case "bytecode":
		return verifierBytecode(args[1:], stdout)
	case "regen":
		return verifierRegen(args[1:], stdout, stderr)
	case "ceremony":
		return verifierCeremony(args[1:], stdout)
	}
	return 2, fmt.Errorf("verifier: unknown action %q (abi, diff, vk, bytecode, regen, ceremony)", args[0])
}

// gnarkInfo reads the gnark versions, backends and features of a repository.
func gnarkInfo(root, version, backend string) (verifier.Gnark, error) {
	g := verifier.Gnark{}
	st, err := detect.Detect(root, Version)
	if err != nil {
		return g, err
	}
	g.Versions = st.Gnark.Versions
	g.Backends = st.Gnark.Backends
	for _, f := range st.Gnark.Features {
		if f == "commitments" {
			g.Commitments = true
		}
	}
	if version != "" {
		g.Versions = []string{version}
	}
	if backend != "" {
		g.Backends = []string{backend}
	}
	return g, nil
}

func verifierABI(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier abi", flag.ContinueOnError)
	repo := repoFlag(fs)
	ver := fs.String("gnark", "", "gnark version to compare with (default: go.mod)")
	backend := fs.String("backend", "", "groth16 or plonk (default: the backends the Go code imports)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	root, err := absRepo(*repo)
	if err != nil {
		return 2, err
	}
	res, err := solidity.ScanRepo(root, nil)
	if err != nil {
		return 2, err
	}
	g, err := gnarkInfo(root, *ver, *backend)
	if err != nil {
		return 2, err
	}
	rep := verifier.CheckABI(res, g)
	code := 0
	if rep.Mismatches() > 0 {
		code = 1
	}
	if *asJSON {
		return code, writeJSON(stdout, rep)
	}
	fmt.Fprint(stdout, verifier.ABIText(rep, g))
	return code, nil
}

func verifierDiff(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier diff", flag.ContinueOnError)
	a := fs.String("a", "", "first verifier source (the committed or deployed one)")
	b := fs.String("b", "", "second verifier source (the regenerated one)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *a == "" || *b == "" {
		return 2, fmt.Errorf("verifier diff: --a and --b are required")
	}
	sa, err := os.ReadFile(*a)
	if err != nil {
		return 2, err
	}
	sb, err := os.ReadFile(*b)
	if err != nil {
		return 2, err
	}
	d := verifier.Diff(*a, string(sa), *b, string(sb))
	if *asJSON {
		return 0, writeJSON(stdout, d)
	}
	fmt.Fprint(stdout, verifier.DiffText(d))
	return 0, nil
}

func verifierVK(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier vk", flag.ContinueOnError)
	sol := fs.String("sol", "", "verifier source")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *sol == "" {
		return 2, fmt.Errorf("verifier vk: --sol is required")
	}
	b, err := os.ReadFile(*sol)
	if err != nil {
		return 2, err
	}
	vk := verifier.VKConstants(string(b))
	if *asJSON {
		if vk == nil {
			vk = []verifier.Constant{}
		}
		return 0, writeJSON(stdout, vk)
	}
	if len(vk) == 0 {
		fmt.Fprintf(stdout, "%s: no named verifying-key constants (not a gnark or snarkjs template, or a template that builds its key in code)\n", *sol)
		return 0, nil
	}
	fmt.Fprintf(stdout, "%s: %d verifying-key constants\n", *sol, len(vk))
	for _, c := range vk {
		fmt.Fprintf(stdout, "%s:%d %s = %s\n", *sol, c.Line, c.Name, c.Value)
	}
	return 0, nil
}

func verifierBytecode(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier bytecode", flag.ContinueOnError)
	deployed := fs.String("deployed", "", "deployed runtime bytecode: a hex file or an artifact JSON")
	rpc := fs.String("rpc", "", "JSON-RPC URL to fetch the deployed code from (network: only when the user asked)")
	address := fs.String("address", "", "verifier address, with --rpc")
	block := fs.String("block", "latest", "block tag or number, with --rpc")
	local := fs.String("local", "", "locally built runtime bytecode: hex or a forge artifact (out/<File>.sol/<Contract>.json)")
	sol := fs.String("sol", "", "verifier source whose VK constants to look for in the deployed code")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	var dep *verifier.Code
	var err error
	switch {
	case *deployed != "" && *rpc != "":
		return 2, fmt.Errorf("verifier bytecode: give --deployed or --rpc, not both")
	case *deployed != "":
		dep, err = verifier.ReadCode(*deployed)
	case *rpc != "":
		dep, err = verifier.FetchCode(context.Background(), *rpc, *address, *block)
	default:
		return 2, fmt.Errorf("verifier bytecode: --deployed FILE or --rpc URL --address 0x... is required")
	}
	if err != nil {
		return 2, err
	}
	var loc *verifier.Code
	if *local != "" {
		if loc, err = verifier.ReadCode(*local); err != nil {
			return 2, err
		}
	}
	var vk []verifier.Constant
	if *sol != "" {
		b, err := os.ReadFile(*sol)
		if err != nil {
			return 2, err
		}
		vk = verifier.VKConstants(string(b))
	}
	if loc == nil && len(vk) == 0 {
		return 2, fmt.Errorf("verifier bytecode: give --local (compare code) or --sol (look for VK constants), or both")
	}
	r := verifier.CompareBytecode(dep, loc, vk)
	if *asJSON {
		return 0, writeJSON(stdout, r)
	}
	fmt.Fprintf(stdout, "deployed: %s (%d bytes)\n", r.Deployed, r.DeployedSize)
	if r.Local != "" {
		fmt.Fprintf(stdout, "local:    %s (%d bytes)\n", r.Local, r.LocalSize)
		fmt.Fprintf(stdout, "code:     %s: %s\n", r.Match, r.Detail)
	}
	if r.VKChecked > 0 {
		fmt.Fprintf(stdout, "vk:       %d of %d VK constants of %s found in the deployed code: %s\n", len(r.VKFound), r.VKChecked, *sol, r.VKExtractNote)
		if len(r.VKMissing) > 0 {
			fmt.Fprintf(stdout, "missing:  %s\n", strings.Join(r.VKMissing, ", "))
		}
	}
	return 0, nil
}

func verifierRegen(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier regen", flag.ContinueOnError)
	repo := repoFlag(fs)
	out := fs.String("out", "", "audit output directory (required); work happens in <out>/regen")
	mainPkg := fs.String("main", "", "repository-relative directory of the target's export program (package main calling ExportSolidity)")
	vk := fs.String("vk", "", "verifying-key file to export the verifier from (gnark binary format)")
	circuit := fs.String("circuit", "", "<package dir>.<Type>: compile the circuit, run a throwaway setup, export")
	backend := fs.String("backend", "groth16", "groth16 or plonk (with --vk or --circuit)")
	compare := fs.String("compare", "", "committed verifier source to diff the result with")
	sb := fs.String("sandbox", "auto", "auto (OS sandbox when available), on (required) or off (limits only)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("verifier regen: --out is required")
	}
	root, err := absRepo(*repo)
	if err != nil {
		return 2, err
	}
	if err := refuseInRepo("verifier regen --out", *out, root); err != nil {
		return 2, err
	}
	opt := verifier.RegenOptions{Repo: root, Out: *out, Main: *mainPkg, VK: *vk, Circuit: *circuit, Backend: *backend, Stderr: stderr}
	switch *sb {
	case "auto":
	case "on":
		opt.Require = true
	case "off":
		opt.Engine = "none"
	default:
		return 2, fmt.Errorf("verifier regen: --sandbox wants auto, on or off")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return 2, err
	}
	res, err := verifier.Regen(opt)
	if err != nil {
		if res != nil && res.Log != "" {
			fmt.Fprintln(stdout, res.Log)
		}
		return 1, err
	}
	fmt.Fprintf(stdout, "regenerated with gnark %s (module %s, mode %s, sandbox %s):\n", res.Gnark, res.Module, res.Mode, res.Engine)
	for _, v := range res.Verifiers {
		fmt.Fprintf(stdout, "  %s\n", v)
	}
	if err := writeJSONFile(filepath.Join(*out, "regen", "regen.json"), res); err != nil {
		return 2, err
	}
	if *compare != "" {
		committed, err := os.ReadFile(*compare)
		if err != nil {
			return 2, err
		}
		got, err := os.ReadFile(res.Verifiers[0])
		if err != nil {
			return 2, err
		}
		d := verifier.Diff(*compare, string(committed), res.Verifiers[0], string(got))
		if err := writeJSONFile(filepath.Join(*out, "regen", "diff.json"), d); err != nil {
			return 2, err
		}
		fmt.Fprint(stdout, verifier.DiffText(d))
	}
	return 0, nil
}

func verifierCeremony(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verifier ceremony", flag.ContinueOnError)
	repo := repoFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	root, err := absRepo(*repo)
	if err != nil {
		return 2, err
	}
	c, err := verifier.ScanCeremony(root)
	if err != nil {
		return 2, err
	}
	if *asJSON {
		return 0, writeJSON(stdout, c)
	}
	fmt.Fprint(stdout, verifier.CeremonyText(c))
	return 0, nil
}
