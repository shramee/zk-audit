package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/criticcheck"
)

// cmdCriticCheck lists the missing units the tool can compute (Phase 5),
// writes <out>/critic-check.json, and with --verify fails while an item has
// no recorded decision in the ledger.
func cmdCriticCheck(argv []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("critic-check", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	verify := fs.Bool("verify", false, "check that every item of the saved critic-check.json has a decision in the ledger (exit 1 otherwise)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(argv); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("critic-check: --out is required")
	}
	if *verify {
		open, err := criticcheck.Undecided(*out)
		if err != nil {
			return 2, err
		}
		if len(open) == 0 {
			fmt.Fprintln(stdout, "OK critic-check: every missing unit has a decision")
			return 0, nil
		}
		for _, it := range open {
			fmt.Fprintf(stdout, "undecided: %s %s (%s) — run it in the targeted wave (ledger mark --wave N), defer it, or dismiss it with a reason\n", it.Kind, it.ID, orUnit(it))
		}
		fmt.Fprintf(stdout, "FAIL critic-check: %d missing units have no decision\n", len(open))
		return 1, nil
	}
	res, err := criticcheck.Check(*out)
	if err != nil {
		return 2, err
	}
	if err := writeJSONFile(filepath.Join(*out, criticcheck.File), res); err != nil {
		return 2, err
	}
	if *asJSON {
		return 0, writeJSON(stdout, res)
	}
	fmt.Fprintf(stdout, "%d missing units from %d agent outputs (%s)\n", len(res.MissingUnits), res.Outputs, counts(res.Counts))
	if len(res.MissingUnits) > 0 {
		fmt.Fprintln(stdout, "| Kind | Item | Lens | Ledger unit | Why |\n|---|---|---|---|---|")
		for _, it := range res.MissingUnits {
			fmt.Fprintf(stdout, "| %s | %s | %s | %s | %s |\n", it.Kind, it.ID, it.Lens, orUnit(it), it.Why)
		}
	}
	return 0, nil
}

func orUnit(it criticcheck.Item) string {
	if it.Unit != "" {
		return it.Unit
	}
	return "none: " + it.Add
}

func counts(m map[string]int) string {
	var s []string
	for _, k := range []string{"unit-open", "unit-no-output", "hint", "public-input", "verify-call", "privileged", "entry-point", "gadget"} {
		if m[k] > 0 {
			s = append(s, fmt.Sprintf("%s %d", k, m[k]))
		}
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
