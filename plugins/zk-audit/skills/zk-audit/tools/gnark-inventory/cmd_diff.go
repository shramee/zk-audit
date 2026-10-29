package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/diff"
)

// cmdDiff lists the changed files between the merge base of --base and
// --head and flags diff mode's high-risk triggers. With --out it writes
// diff.json and diff.md there and prints the Markdown; otherwise it prints
// the JSON.
func cmdDiff(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	repo := repoFlag(fs)
	base := fs.String("base", "origin/main", "base revision (the merge base with --head is compared)")
	head := fs.String("head", "HEAD", "head revision")
	out := fs.String("out", "", "write diff.json and diff.md to this directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := absRepo(*repo)
	if err != nil {
		return err
	}
	res, err := diff.Compare(root, *base, *head)
	if err != nil {
		return fmt.Errorf("diff: %w", err)
	}
	if *out == "" {
		return writeJSON(stdout, res)
	}
	if err := refuseInRepo("diff --out", *out, root); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(*out, "diff.json"), res); err != nil {
		return err
	}
	md := res.Markdown()
	if err := os.WriteFile(filepath.Join(*out, "diff.md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Fprint(stdout, md)
	fmt.Fprintf(stdout, "\nwrote %s/{diff.json,diff.md}\n", *out)
	return nil
}
