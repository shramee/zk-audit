package verifier

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/gomod"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/sandbox"
)

// RegenOptions configure Regen. Exactly one of Main, VK and Circuit is set.
type RegenOptions struct {
	Repo string // the audited repository (read-only; copied)
	Out  string // the audit output directory; Regen works in <Out>/regen
	// Main is the repository-relative directory of the target's own export
	// program (a package main that calls ExportSolidity). It runs with the
	// target's gnark, its production circuit shapes and its own setup.
	Main string
	// VK is a verifying-key file (gnark binary, WriteTo/WriteRawTo). Regen
	// exports the verifier gnark makes from it, so its VK constants can be
	// compared with the committed or deployed verifier's.
	VK string
	// Circuit is "<repository-relative package dir>.<Type>": compile a zero
	// value of the type, run a fresh setup and export. The VK differs from
	// any committed one; only the structure is comparable.
	Circuit string
	Backend string // groth16 (default) or plonk, for VK and Circuit
	Engine  string // sandbox engine: auto (default), bwrap, sandbox-exec, none
	Require bool   // fail without an OS sandbox
	Timeout time.Duration
	Stderr  io.Writer
}

// RegenResult says what ran and what it wrote.
type RegenResult struct {
	Mode      string   `json:"mode"`
	Module    string   `json:"module"`
	Gnark     string   `json:"gnark"`
	Build     []string `json:"build_command"`
	Run       []string `json:"run_command"`
	Engine    string   `json:"sandbox"`
	Verifiers []string `json:"verifiers"`
	Output    string   `json:"output_dir"`
	Log       string   `json:"log_tail,omitempty"`
}

// skipCopy are directory names not copied into the scratch tree.
var skipCopy = map[string]bool{".git": true, "node_modules": true, ".zk-audit": true, "out": true, "cache": true, "artifacts": true, "broadcast": true}

const maxCopyFile = 64 << 20

// Regen regenerates the Solidity verifier with the target's own gnark
// version, inside the sandbox: it copies the repository to
// <out>/regen/src (the original stays read-only), builds the export
// program there, and runs it with <out>/regen/output as its only writable
// directory and working directory. Nothing touches the network (GOPROXY
// off); the target's modules must be in the module cache.
func Regen(opt RegenOptions) (*RegenResult, error) {
	n := 0
	for _, s := range []string{opt.Main, opt.VK, opt.Circuit} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("regen: give exactly one of --main, --vk and --circuit")
	}
	if opt.Backend == "" {
		opt.Backend = "groth16"
	}
	if opt.Backend != "groth16" && opt.Backend != "plonk" {
		return nil, fmt.Errorf("regen: --backend wants groth16 or plonk")
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	repo, err := filepath.Abs(opt.Repo)
	if err != nil {
		return nil, err
	}
	work, err := filepath.Abs(filepath.Join(opt.Out, "regen"))
	if err != nil {
		return nil, err
	}
	if fsutil.Inside(work, repo) {
		return nil, fmt.Errorf("regen: the output directory %s is inside the audited repository", work)
	}
	if err := os.RemoveAll(work); err != nil {
		return nil, err
	}
	src := filepath.Join(work, "src")
	outDir := filepath.Join(work, "output")
	binDir := filepath.Join(work, "bin")
	for _, d := range []string{src, outDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := copyTree(repo, src); err != nil {
		return nil, fmt.Errorf("regen: copy: %w", err)
	}
	// the module that holds the program
	pkgDir := opt.Main
	var typeName string
	if opt.Circuit != "" {
		i := strings.LastIndex(opt.Circuit, ".")
		if i <= 0 {
			return nil, fmt.Errorf("regen: --circuit wants <package dir>.<Type>, e.g. circuits/vote.VoteCircuit")
		}
		pkgDir, typeName = opt.Circuit[:i], opt.Circuit[i+1:]
	}
	modRel, modPath, gnarkVer, err := findModule(repo, pkgDir)
	if err != nil {
		return nil, err
	}
	res := &RegenResult{Module: modRel, Gnark: gnarkVer, Output: outDir}
	modDir := filepath.Join(src, filepath.FromSlash(modRel))
	var target string
	var runArgs []string
	ro := []string{repo}
	switch {
	case opt.Main != "":
		res.Mode = "main"
		rel, err := filepath.Rel(modDir, filepath.Join(src, filepath.FromSlash(opt.Main)))
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("regen: --main %s is outside module %s", opt.Main, modRel)
		}
		target = "./" + filepath.ToSlash(rel)
	default:
		res.Mode = "vk"
		var prog string
		if opt.VK != "" {
			vk, err := filepath.Abs(opt.VK)
			if err != nil {
				return nil, err
			}
			if _, err := os.Stat(vk); err != nil {
				return nil, fmt.Errorf("regen: --vk: %w", err)
			}
			ro = append(ro, filepath.Dir(vk))
			runArgs = []string{vk}
			prog = vkProgram(opt.Backend)
		} else {
			res.Mode = "circuit"
			importPath := modPath
			rel, err := filepath.Rel(filepath.Join(repo, filepath.FromSlash(modRel)), filepath.Join(repo, filepath.FromSlash(pkgDir)))
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil, fmt.Errorf("regen: --circuit package %s is outside module %s", pkgDir, modRel)
			}
			if rel != "." {
				importPath += "/" + filepath.ToSlash(rel)
			}
			prog = circuitProgram(opt.Backend, importPath, typeName)
		}
		dir := filepath.Join(modDir, "zkaudit_regen")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(prog), 0o644); err != nil {
			return nil, err
		}
		target = "./zkaudit_regen"
	}
	bin := filepath.Join(binDir, "export")
	res.Build = []string{"go", "-C", modDir, "build", "-o", bin, target}
	res.Run = append([]string{bin}, runArgs...)
	var log bytes.Buffer
	so := sandbox.Options{RW: []string{work}, RO: ro, Cwd: outDir, Engine: opt.Engine, Require: opt.Require,
		Timeout: opt.Timeout, Stdout: &log, Stderr: &log}
	code, eng, err := sandbox.Run(res.Build, so)
	if eng != nil {
		res.Engine = eng.Name
	}
	if err != nil {
		return res, err
	}
	if code != 0 {
		res.Log = tail(log.String(), 40)
		return res, fmt.Errorf("regen: building %s failed (exit %d); are the target's modules in the module cache? %s", target, code, res.Log)
	}
	log.Reset()
	code, _, err = sandbox.Run(res.Run, so)
	if err != nil {
		return res, err
	}
	res.Log = tail(log.String(), 40)
	if code != 0 {
		return res, fmt.Errorf("regen: the export program exited %d: %s", code, res.Log)
	}
	err = filepath.WalkDir(outDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".sol") {
			res.Verifiers = append(res.Verifiers, p)
		}
		return nil
	})
	sort.Strings(res.Verifiers)
	if len(res.Verifiers) == 0 {
		return res, fmt.Errorf("regen: the program wrote no .sol file into %s (it may write elsewhere or need input files; read it and run the matching mode)", outDir)
	}
	return res, err
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// findModule returns the repository-relative directory of the go.mod that
// owns pkgDir (or, with pkgDir empty, the first one that requires gnark),
// its module path and its gnark version.
func findModule(repo, pkgDir string) (string, string, string, error) {
	mods, err := fsutil.Walk(repo, func(rel string) bool { return path.Base(rel) == "go.mod" })
	if err != nil {
		return "", "", "", err
	}
	best := ""
	var bestMod *gomod.File
	for _, m := range mods {
		f, err := gomod.ParseFile(m.Abs)
		if err != nil {
			continue
		}
		dir := path.Dir(m.Rel)
		if pkgDir != "" {
			if dir == "." || pkgDir == dir || strings.HasPrefix(path.Clean(pkgDir)+"/", dir+"/") {
				if bestMod == nil || len(dir) > len(best) {
					best, bestMod = dir, f
				}
			}
			continue
		}
		if _, _, ok := f.Version("github.com/consensys/gnark"); ok && bestMod == nil {
			best, bestMod = dir, f
		}
	}
	if bestMod == nil {
		return "", "", "", fmt.Errorf("regen: no go.mod owns %q", pkgDir)
	}
	v, by, _ := bestMod.Version("github.com/consensys/gnark")
	if v == "" && by != "" {
		v = "replaced by " + by
	}
	if v == "" {
		return "", "", "", fmt.Errorf("regen: module %s does not require gnark", best)
	}
	return best, bestMod.Module, v, nil
}

func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != from && skipCopy[d.Name()] {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and devices are not followed
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxCopyFile {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
}

var reIdentOnly = regexp.MustCompile(`^[A-Za-z_]\w*$`)

func vkProgram(backend string) string {
	return `// Code written by gnark-inventory verifier regen: export the Solidity
// verifier of a verifying-key file with the module's own gnark.
package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/` + backend + `"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	vk := ` + backend + `.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(f); err != nil {
		fmt.Fprintln(os.Stderr, "read vk:", err)
		os.Exit(1)
	}
	out, err := os.Create("Verifier.sol")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer out.Close()
	if err := vk.ExportSolidity(out); err != nil {
		fmt.Fprintln(os.Stderr, "export:", err)
		os.Exit(1)
	}
}
`
}

func circuitProgram(backend, importPath, typ string) string {
	if !reIdentOnly.MatchString(typ) {
		typ = "Circuit"
	}
	builder, setup := "r1cs", `	_, vk, err := groth16.Setup(ccs)`
	imports := `	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"`
	if backend == "plonk" {
		builder = "scs"
		imports = `	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"`
		setup = `	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "srs:", err)
		os.Exit(1)
	}
	_, vk, err := plonk.Setup(ccs, srs, srsLagrange)`
	}
	return `// Code written by gnark-inventory verifier regen: compile the circuit with
// the module's own gnark, run a throwaway setup and export the verifier.
// Its verifying key is fresh; only the structure is comparable.
package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
` + imports + `

	target "` + importPath + `"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), ` + builder + `.NewBuilder, &target.` + typ + `{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "compile (a circuit with slices needs its production sizes: use --main with the repository's export program):", err)
		os.Exit(1)
	}
` + setup + `
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		os.Exit(1)
	}
	out, err := os.Create("Verifier.sol")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer out.Close()
	if err := vk.ExportSolidity(out); err != nil {
		fmt.Fprintln(os.Stderr, "export:", err)
		os.Exit(1)
	}
}
`
}
