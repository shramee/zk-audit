// Command score grades zk-audit eval runs against a case's answer key.
//
//	score run --key key.json --target DIR --findings findings.json [--label L] [--cost USD] [--duration S] [--json FILE]
//	score summarize RESULT.json...
//	score pilot --human human.json|human.md --target DIR --findings findings.json [--key-out key.json] [--json FILE]
//
// run matches every record and hardening note in findings.json to the key's
// planted items, decoys and other true observations, and prints one JSON
// result. summarize aggregates results (three runs per case) into a markdown
// table with mean, spread and per-item hit rates. Exit status: 0 ok, 2 usage
// or input error. pilot scores a run against a human auditor's findings
// (docs/pilots.md): it builds the key from them, and passes when no high or
// critical finding is missed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: score run|summarize|pilot ...")
		return 2
	}
	var err error
	switch args[0] {
	case "run":
		err = cmdRun(args[1:], stdout)
	case "summarize":
		err = cmdSummarize(args[1:], stdout)
	case "pilot":
		err = cmdPilot(args[1:], stdout)
	default:
		err = fmt.Errorf("unknown subcommand %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(stderr, "score:", err)
		return 2
	}
	return 0
}

func cmdRun(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	keyPath := fs.String("key", "", "answer key (key.json)")
	target := fs.String("target", "", "the audited (sanitized) tree")
	findings := fs.String("findings", "", "the run's findings.json")
	label := fs.String("label", "", "run label")
	cost := fs.Float64("cost", -1, "run cost in USD")
	dur := fs.Float64("duration", -1, "run wall-clock seconds")
	out := fs.String("json", "", "also write the result here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *target == "" || *findings == "" {
		return fmt.Errorf("run: --key, --target and --findings are required")
	}
	k, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	if err := k.resolve(*target); err != nil {
		return err
	}
	var res *Result
	es, ferr := loadFindings(*findings)
	if ferr != nil {
		// A run that produced no findings.json scores zero rather than
		// failing the whole summary.
		res = score(k, nil)
		res.Error = ferr.Error()
	} else {
		res = score(k, es)
	}
	res.Label = *label
	if *cost >= 0 {
		res.CostUSD = cost
	}
	if *dur >= 0 {
		res.DurationS = dur
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
	}
	_, err = stdout.Write(b)
	return err
}

func cmdSummarize(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("summarize: want RESULT.json files")
	}
	var rs []*Result
	for _, p := range args {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r Result
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		rs = append(rs, &r)
	}
	_, err := io.WriteString(stdout, summarize(rs))
	return err
}
