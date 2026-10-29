package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/args"
)

// cmdArgs parses a /zk-audit invocation into JSON. Exit 1 means the
// invocation is invalid; the errors are printed before the JSON.
func cmdArgs(argv []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("args", flag.ContinueOnError)
	repo := repoFlag(fs)
	mode := fs.String("mode", "", "force the mode (recon, diff, setup, audit), as a /zk-audit:<mode> command does")
	runID := fs.String("run-id", "", "use this run id (YYYYMMDD-HHMMSS) instead of the current time")
	home := fs.String("home", "", "home directory for the default output path (default: $HOME)")
	if err := fs.Parse(argv); err != nil {
		return 2, err
	}
	var words []string
	for _, a := range fs.Args() {
		w, err := args.Split(a)
		if err != nil {
			return 2, fmt.Errorf("args: %w", err)
		}
		words = append(words, w...)
	}
	h := *home
	if h == "" {
		h, _ = os.UserHomeDir()
	}
	run, err := args.Parse(words, args.Options{Repo: *repo, Home: h, RunID: *runID, Mode: *mode})
	var ae *args.Error
	switch {
	case errors.As(err, &ae):
		for _, p := range ae.Problems {
			fmt.Fprintln(stdout, "error:", p)
		}
		fmt.Fprintf(stdout, "FAIL args: %d problems; tell the user and stop\n", len(ae.Problems))
		return 1, nil
	case err != nil:
		return 2, err
	}
	return 0, writeJSON(stdout, run)
}
