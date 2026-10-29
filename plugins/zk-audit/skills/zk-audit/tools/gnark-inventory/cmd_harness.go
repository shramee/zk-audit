package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/harness"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
)

// cmdHarness writes the per-gadget PoC harness (library mode) into the PoC
// worktree: a wrapper circuit per gadget plus skipped PoC and differential
// test skeletons. It never writes into the audited repository.
func cmdHarness(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("harness", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory holding inventory.json (required)")
	gadget := fs.String("gadget", "", "gadget id (G3) or name (pkg.Func, pkg.Type.Method) from inventory.json")
	all := fs.Bool("all", false, "every exported gadget outside test files")
	worktree := fs.String("worktree", "", "PoC worktree (default <out>/worktree); the file goes into the gadget's package directory there")
	print := fs.Bool("print", false, "print the harness instead of writing it")
	emparams := fs.String("emparams", "emparams.BN254Fp", "concrete emulated.FieldParams for generic gadgets")
	curve := fs.String("curve", "BN254", "ecc curve id of the native field")
	external := fs.Bool("external", false, "write the external test package (<pkg>_test); use it when the in-package harness import-cycles (gnark std)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" || (*gadget == "") == !*all {
		return 2, fmt.Errorf("harness: want --out DIR and one of --gadget ID|NAME or --all")
	}
	raw, err := os.ReadFile(filepath.Join(*out, "inventory.json"))
	if err != nil {
		return 2, fmt.Errorf("harness: %w (run `inventory` first)", err)
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return 2, fmt.Errorf("harness: inventory.json: %w", err)
	}
	var picked []*inventory.Gadget
	for _, g := range inv.Gadgets {
		if g.InTest {
			continue
		}
		if *all || g.ID == *gadget || g.Name == *gadget {
			picked = append(picked, g)
		}
	}
	if len(picked) == 0 {
		return 1, fmt.Errorf("harness: no gadget %q in %s/inventory.json (gnark-inventory inventory lists them under gadgets)", *gadget, *out)
	}
	wt := *worktree
	if wt == "" {
		wt = filepath.Join(*out, "worktree")
	}
	opt := harness.Options{EmParams: *emparams, Curve: *curve, External: *external}
	for _, g := range picked {
		src, err := harness.Generate(&inv, g, opt)
		if err != nil {
			return 1, err
		}
		if *print {
			fmt.Fprint(stdout, src)
			continue
		}
		dir := filepath.Join(wt, filepath.FromSlash(g.Package))
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return 2, fmt.Errorf("harness: %s is not a directory: create the PoC worktree first (git -C <repo> worktree add --detach %s HEAD)", dir, wt)
		}
		dest := filepath.Join(dir, harness.FileName(g))
		if inv.Repo != "" && fsutil.Inside(dest, inv.Repo) {
			return 2, fmt.Errorf("harness: %s is inside the audited repository %s; the harness goes into the PoC worktree only", dest, inv.Repo)
		}
		if err := os.WriteFile(dest, []byte(src), 0o644); err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "%s %s → %s\n", g.ID, g.Name, dest)
	}
	return 0, nil
}
