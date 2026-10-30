package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/estimate"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
)

// cmdEstimate predicts agents, tokens, cost and time per profile from
// <out>/inventory.json, before any agent is spawned. It writes
// <out>/estimate.json and prints a table (or the JSON with --json).
func cmdEstimate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("estimate", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory holding inventory.json (required)")
	var profiles listFlag
	fs.Var(&profiles, "profile", "profile to estimate (repeatable; default: every profile)")
	passes := fs.Int("passes", 0, "passes (--loop N); default: the profile's")
	noPoC := fs.Bool("no-poc", false, "no PoC builders (--no-poc)")
	asJSON := fs.Bool("json", false, "print JSON instead of the table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("estimate: --out is required")
	}
	b, err := os.ReadFile(filepath.Join(*out, "inventory.json"))
	if err != nil {
		return fmt.Errorf("estimate: %w (run `inventory` first)", err)
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return fmt.Errorf("estimate: inventory.json: %w", err)
	}
	rep, err := estimate.Profiles(&inv, profiles, estimate.Options{Passes: *passes, NoPoC: *noPoC})
	if err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "estimate.json"), rep); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, rep)
	}
	fmt.Fprint(stdout, rep.Markdown())
	return nil
}
