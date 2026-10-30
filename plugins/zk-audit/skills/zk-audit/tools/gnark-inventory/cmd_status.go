package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/status"
)

// cmdStatus prints how far the run in an output directory got and the next
// step, for `/zk-audit resume`.
func cmdStatus(argv []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("status: --out is required")
	}
	s, err := status.Read(*out)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, s)
	}
	fmt.Fprint(stdout, s.Text())
	return nil
}
