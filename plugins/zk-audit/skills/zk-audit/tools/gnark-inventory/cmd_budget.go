package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/args"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/budget"
)

// loadSpend reads <out>/spend.json and fills the profile and budget from
// <out>/run.json when the ledger does not have them yet.
func loadSpend(out string) (*budget.Ledger, error) {
	l, _, err := budget.Load(out)
	if err != nil {
		return nil, err
	}
	if r, err := args.Load(out); err == nil {
		if l.Profile == "" {
			l.Profile = r.Profile
		}
		if r.BudgetUSD > 0 {
			l.BudgetUSD = r.BudgetUSD
		}
	}
	return l, nil
}

// recordSpend appends one agent attempt to <out>/spend.json.
func recordSpend(out string, e budget.Entry) (*budget.Ledger, error) {
	l, err := loadSpend(out)
	if err != nil {
		return nil, err
	}
	if err := l.Record(e); err != nil {
		return nil, err
	}
	return l, l.Save(out)
}

// cmdBudget keeps the spend ledger: `record` adds an agent that was not
// saved with `agents save` (PoC builders, refuters, the companion),
// `check` decides before a wave whether it fits the --budget ceiling,
// `show` prints the totals.
func cmdBudget(argv []string, stdout io.Writer) (int, error) {
	if len(argv) == 0 {
		return 2, fmt.Errorf("budget: want record, check or show")
	}
	sub, argv := argv[0], argv[1:]
	fs := flag.NewFlagSet("budget "+sub, flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	var e budget.Entry
	w := budget.Wave{}
	var before string
	var ceiling float64
	asJSON := fs.Bool("json", false, "print JSON")
	switch sub {
	case "record":
		fs.StringVar(&e.ID, "id", "", "agent id (poc-3, refuter-3, solidity-auditor, ...)")
		fs.StringVar(&e.Role, "role", "", "hunter, critic, wave, poc, refuter, companion, other (default: from the id)")
		fs.StringVar(&e.Status, "status", "done", "done, blocked, failed or refused")
		fs.IntVar(&e.Tokens, "tokens", 0, "tokens the runtime reported (subagent_tokens); 0: not shown")
		fs.IntVar(&e.ToolUses, "tool-uses", 0, "tool uses the runtime reported")
		fs.IntVar(&e.DurationMS, "duration-ms", 0, "duration the runtime reported, in ms")
		fs.StringVar(&e.Model, "model", "", "model the runtime ran the agent on, when shown")
	case "check":
		fs.StringVar(&before, "before", "", "the wave about to start, e.g. \"hunt pass 1\", \"PoC builders\" (required)")
		for _, r := range budget.Roles {
			r := r
			fs.Func(r, "agents of role "+r+" in the next wave", func(v string) error {
				var n int
				if _, err := fmt.Sscan(v, &n); err != nil || n < 0 {
					return fmt.Errorf("--%s wants a count", r)
				}
				w[r] += n
				return nil
			})
		}
		fs.Float64Var(&ceiling, "budget", 0, "budget in USD (default: run.json's --budget)")
	case "show":
	default:
		return 2, fmt.Errorf("budget: unknown action %q (want record, check or show)", sub)
	}
	if err := fs.Parse(argv); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("budget %s: --out is required", sub)
	}
	switch sub {
	case "record":
		l, err := recordSpend(*out, e)
		if err != nil {
			fmt.Fprintln(stdout, "error:", err)
			return 1, nil
		}
		fmt.Fprintln(stdout, "spend:", l.Summary())
	case "check":
		if before == "" {
			return 2, fmt.Errorf("budget check: --before is required")
		}
		l, err := loadSpend(*out)
		if err != nil {
			return 2, err
		}
		if ceiling > 0 {
			l.BudgetUSD = ceiling
		}
		d := l.Check(before, w, ceiling)
		if err := l.Save(*out); err != nil {
			return 2, err
		}
		if err := writeJSON(stdout, d); err != nil {
			return 2, err
		}
	case "show":
		l, err := loadSpend(*out)
		if err != nil {
			return 2, err
		}
		if *asJSON {
			return 0, writeJSON(stdout, struct {
				*budget.Ledger
				Totals budget.Totals `json:"totals"`
			}{l, l.Totals()})
		}
		fmt.Fprintln(stdout, "spend:", l.Summary())
		if l.Stopped != nil {
			fmt.Fprintln(stdout, "stopped:", l.Stopped.Reason)
		}
	}
	return 0, nil
}
