package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/threatmodel"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// cmdThreatModel parses <repo>/zk-audit.md into <out>/threat-model.json.
// Exit 1 lists every problem and writes nothing; a repository without the
// file is not an error.
func cmdThreatModel(argv []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("threat-model", flag.ContinueOnError)
	repo := repoFlag(fs)
	out := fs.String("out", "", "audit output directory: write threat-model.json there")
	file := fs.String("file", "", "threat-model file (default <repo>/zk-audit.md)")
	asJSON := fs.Bool("json", false, "print the parsed JSON")
	if err := fs.Parse(argv); err != nil {
		return 2, err
	}
	root, err := absRepo(*repo)
	if err != nil {
		return 2, err
	}
	d, ok, err := threatmodel.Load(root, *file)
	var te *threatmodel.Error
	switch {
	case errors.As(err, &te):
		for _, p := range te.Problems {
			fmt.Fprintln(stdout, "error:", p)
		}
		fmt.Fprintf(stdout, "FAIL threat-model: %d problems; fix zk-audit.md (template: {skill}/templates/zk-audit.md)\n", len(te.Problems))
		return 1, nil
	case err != nil:
		return 2, err
	case !ok:
		fmt.Fprintf(stdout, "no %s at %s: the run has no threat model; recon offers to draft one from {skill}/templates/zk-audit.md\n", threatmodel.FileName, root)
		return 0, nil
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return 2, err
	}
	rep, err := validate.Document("threat-model", b)
	if err != nil {
		return 2, err
	}
	if !rep.OK() {
		for _, e := range rep.Errors {
			fmt.Fprintln(stdout, "error:", e)
		}
		return 1, nil
	}
	for _, w := range d.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	if *out != "" {
		p := filepath.Join(*out, threatmodel.OutName)
		if err := refuseInRepo("--out", *out, root); err != nil {
			return 2, err
		}
		if err := writeJSONFile(p, d); err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "wrote %s: ", p)
	}
	fmt.Fprintf(stdout, "%d in-scope paths, %d out of scope, %d trusted parties, %d properties, %d accepted risks, %d prior findings, %d deployment facts\n",
		len(d.Scope.In), len(d.Scope.Out), len(d.TrustedParties), len(d.Properties), len(d.AcceptedRisks), len(d.PriorFindings), len(d.Deployment))
	if *asJSON {
		return 0, writeJSON(stdout, d)
	}
	return 0, nil
}
