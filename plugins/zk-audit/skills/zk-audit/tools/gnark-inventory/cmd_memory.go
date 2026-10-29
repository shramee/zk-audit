package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/memory"
)

// cmdMemory runs loop mode's memory ledger: init, merge (one pass), known
// (the list later bundles inline) and status (seen in k/N passes).
func cmdMemory(args []string, stdout io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("memory: want init, merge, known or status")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("memory "+sub, flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	var passes, pass *int
	var findings, critic *string
	switch sub {
	case "init":
		passes = fs.Int("passes", 0, "number of planned passes (the args JSON's passes)")
	case "merge":
		pass = fs.Int("pass", 0, "the pass to merge (1, 2, ...)")
		findings = fs.String("findings", "", "the pass's judged records (default <out>/passes/<pass>/findings.json)")
		critic = fs.String("critic", "", "the coverage critic's return for this pass ({\"missing_units\": [...]})")
	case "known", "status":
	default:
		return 2, fmt.Errorf("memory: unknown action %q (want init, merge, known or status)", sub)
	}
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("memory %s: --out is required", sub)
	}
	switch sub {
	case "init":
		m, err := memory.Init(*out, *passes)
		if err != nil {
			fmt.Fprintln(stdout, "error:", err)
			return 1, nil
		}
		fmt.Fprintf(stdout, "memory: %d passes planned, %d merged · %s\n", m.PassesPlanned, len(m.Passes), memory.Path(*out))
		return 0, nil
	case "merge":
		f := *findings
		if f == "" {
			f = memory.PassFindings(*out, *pass)
		}
		doc, err := os.ReadFile(f)
		if err != nil {
			return 2, err
		}
		missing, given := 0, false
		if *critic != "" {
			b, err := os.ReadFile(*critic)
			if err != nil {
				return 2, err
			}
			if missing, err = memory.MissingUnits(b); err != nil {
				fmt.Fprintln(stdout, "error:", err)
				return 1, nil
			}
			given = true
		}
		res, err := memory.Merge(*out, *pass, doc, missing, given)
		if err != nil {
			fmt.Fprintln(stdout, "error:", err)
			return 1, nil
		}
		return 0, writeJSON(stdout, res)
	}
	m, ok, err := memory.Load(*out)
	if err != nil {
		return 2, err
	}
	if !ok {
		fmt.Fprintln(stdout, "no memory.json (not a loop run)")
		return 0, nil
	}
	if sub == "known" {
		fmt.Fprint(stdout, m.Known())
	} else {
		fmt.Fprint(stdout, m.Status())
	}
	return 0, nil
}
