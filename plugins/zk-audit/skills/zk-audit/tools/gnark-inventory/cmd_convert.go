package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/companion"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
)

const convertUsage = `gnark-inventory convert: companion output to zk-audit records

  convert pashov --in PATH --out FILE [--inventory FILE]
      Read pashov solidity-auditor output (a .solidity-auditor/runs/<stamp>
      directory with run-K.md files, one run-K.md, or full-report.md) and
      write lead records with detected_by: solidity-auditor, one per
      finding or lead key, resolved to file and line through inventory.json.
      Items whose contract the inventory does not know are listed under
      "unresolved", never dropped.
`

// cmdConvert dispatches `convert <companion>`.
func cmdConvert(args []string, stdout io.Writer) (int, error) {
	if len(args) < 1 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, convertUsage)
		if len(args) < 1 {
			return 2, nil
		}
		return 0, nil
	}
	if args[0] != "pashov" {
		return 2, fmt.Errorf("convert: unknown companion %q (pashov)", args[0])
	}
	fs := flag.NewFlagSet("convert pashov", flag.ContinueOnError)
	in := fs.String("in", "", "solidity-auditor runs directory, run-K.md or full-report.md (required)")
	out := fs.String("out", "", "write the records here, e.g. <out>/companions/solidity-auditor.json (required)")
	invPath := fs.String("inventory", "", "inventory.json of this audit, to resolve Contract.function to file:line")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	if *in == "" || *out == "" {
		return 2, fmt.Errorf("convert pashov: --in and --out are required")
	}
	var inv *inventory.Inventory
	if *invPath != "" {
		b, err := os.ReadFile(*invPath)
		if err != nil {
			return 2, err
		}
		inv = &inventory.Inventory{}
		if err := json.Unmarshal(b, inv); err != nil {
			return 2, fmt.Errorf("convert pashov: %s: %w", *invPath, err)
		}
		if err := refuseInRepo("convert --out", *out, inv.Repo); err != nil {
			return 2, err
		}
	}
	res, err := companion.ConvertPashov(companion.Options{In: *in, Inventory: inv})
	if err != nil {
		return 2, err
	}
	if inv == nil {
		res.Warnings = append(res.Warnings, "no --inventory: no item can be resolved to a file and line")
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return 2, err
	}
	if err := writeJSONFile(*out, res); err != nil {
		return 2, err
	}
	findings := 0
	for _, it := range res.Items {
		if it.Kind == "FINDING" {
			findings++
		}
	}
	fmt.Fprintf(stdout, "%s (%s, %d run(s)): %d records (%d companion findings, %d leads, all as leads for judging), %d unresolved -> %s\n",
		companion.Pashov, res.Format, res.Runs, len(res.Records), findings, len(res.Records)-findings, len(res.Unresolved), *out)
	for _, w := range res.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for _, u := range res.Unresolved {
		fmt.Fprintf(stdout, "unresolved: %s %q at %s: %s\n", u.Kind, u.Title, u.Location, u.Reason)
	}
	return 0, nil
}
