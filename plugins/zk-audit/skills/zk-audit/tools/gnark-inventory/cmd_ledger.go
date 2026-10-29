package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/agents"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/ledger"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

// cmdLedger edits coverage-ledger.json in place: `ledger mark` changes the
// status and evidence of selected units, `ledger add` adds a unit a critic
// found, `ledger show` prints the counts. Every edit is validated (with the
// output directory checks) before it is written; exit 1 writes nothing.
func cmdLedger(args []string, stdout io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("ledger: want mark, add or show")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("ledger "+sub, flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	path := fs.String("ledger", "", "ledger file (default <out>/coverage-ledger.json)")
	var ids, agentIDs, reviewed, fps, lenses listFlag
	var sel ledger.Selector
	var ch ledger.Change
	var u ledger.Unit
	var unitPath string
	switch sub {
	case "mark":
		fs.Var(&ids, "unit", "unit id to change (repeatable)")
		fs.StringVar(&sel.Match, "match", "", "change units whose id contains this text")
		fs.StringVar(&sel.Lens, "lens", "", "change units that list this lens")
		fs.StringVar(&sel.Kind, "kind", "", "change units of this kind")
		fs.StringVar(&sel.Class, "class", "", "change units of this class")
		fs.StringVar(&sel.Status, "from", "", "only units currently in this status")
		fs.StringVar(&ch.Status, "status", "", "new status: covered, candidate, blocked, deferred, not_applicable, out_of_scope, in_progress, planned")
		fs.Var(&agentIDs, "agent", "agent id to add to agent_ids (repeatable)")
		fs.Var(&reviewed, "reviewed", "repository-relative path to add to reviewed_paths (repeatable)")
		fs.Var(&fps, "fingerprint", "fingerprint to add to result_fingerprints (repeatable)")
		fs.StringVar(&ch.Reason, "reason", "", "reason (required for blocked, deferred, not_applicable, out_of_scope)")
		fs.StringVar(&ch.Notes, "notes", "", "notes")
		fs.IntVar(&ch.Wave, "wave", 0, "wave number")
	case "add":
		fs.StringVar(&u.Kind, "kind", "", "unit kind (circuit, hint, public-input, contract-fn, verifier, role, setup, prover, dependency)")
		fs.StringVar(&u.Subject, "subject", "", "subject (circuit, function, input)")
		fs.StringVar(&u.Class, "class", "", "ledger class (gnark-inventory profiles lists the classes per lens)")
		fs.Var(&lenses, "lens", "lens id (repeatable)")
		fs.StringVar(&unitPath, "path", "", "file:line of the subject")
		fs.StringVar(&u.Notes, "notes", "", "why the unit was added (e.g. coverage critic)")
	case "show":
	default:
		return 2, fmt.Errorf("ledger: unknown action %q (want mark, add or show)", sub)
	}
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("ledger %s: --out is required", sub)
	}
	if *path == "" {
		*path = filepath.Join(*out, "coverage-ledger.json")
	}
	l, err := ledger.Load(*path)
	if err != nil {
		return 2, err
	}
	var changed []string
	switch sub {
	case "show":
		fmt.Fprintf(stdout, "%d units: %s\n", len(l.Units), strings.Join(l.Counts(), " "))
		for _, u := range l.Units {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", u.Status, u.ID, strings.Join(u.AgentIDs, ","))
		}
		return 0, nil
	case "mark":
		sel.IDs, ch.Agents, ch.Reviewed, ch.Fingerprints = ids, agentIDs, reviewed, fps
		if changed, err = l.Mark(sel, ch); err != nil {
			fmt.Fprintln(stdout, "error:", err)
			return 1, nil
		}
	case "add":
		u.Lenses = lenses
		if unitPath != "" {
			u.Paths = []string{unitPath}
		}
		id, err := l.Add(u)
		if err != nil {
			fmt.Fprintln(stdout, "error:", err)
			return 1, nil
		}
		changed = []string{id}
	}
	b, err := l.Marshal()
	if err != nil {
		return 2, err
	}
	rep, err := validate.DocumentWith("ledger", b, validate.Options{Out: *out})
	if err != nil {
		return 2, err
	}
	if !rep.OK() {
		for _, e := range rep.Errors {
			fmt.Fprintln(stdout, "error:", e)
		}
		fmt.Fprintf(stdout, "FAIL ledger %s: %d errors; nothing written\n", sub, len(rep.Errors))
		return 1, nil
	}
	if err := ledger.WriteAtomic(*path, b); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "ledger %s: %d units (%s) · %s\n", sub, len(changed), strings.Join(firstN(changed, 5), ", "), strings.Join(l.Counts(), " "))
	return 0, nil
}

func firstN(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(append([]string{}, xs[:n]...), fmt.Sprintf("… %d more", len(xs)-n))
}

// cmdAgents saves an agent's raw return: `agents save --out DIR --id ID
// [--from FILE] [--status S] [--reason R]`; without --from it reads stdin.
// `agents list --out DIR` prints the index.
func cmdAgents(args []string, stdout io.Writer, stdin io.Reader) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("agents: want save or list")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("agents "+sub, flag.ContinueOnError)
	out := fs.String("out", "", "audit output directory (required)")
	id := fs.String("id", "", "agent id (C1, V-hints, C1@circuit/vote, critic, ...)")
	from := fs.String("from", "", "file holding the agent's return (default: stdin)")
	status := fs.String("status", "done", "done, blocked, failed or refused")
	reason := fs.String("reason", "", "why the agent did not finish (required unless done)")
	if sub != "save" && sub != "list" {
		return 2, fmt.Errorf("agents: unknown action %q (want save or list)", sub)
	}
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *out == "" {
		return 2, fmt.Errorf("agents %s: --out is required", sub)
	}
	if sub == "list" {
		idx, err := agents.Load(*out)
		if err != nil {
			return 2, err
		}
		for _, e := range idx.Agents {
			fmt.Fprintf(stdout, "%s\t%s\t%d findings, %d leads\t%s\n", e.ID, e.Status, e.Findings, e.Leads, e.Reason)
		}
		return 0, nil
	}
	var content []byte
	var err error
	switch {
	case *from != "" && *from != "-":
		content, err = os.ReadFile(*from)
	case *status == "done" || *from == "-":
		content, err = io.ReadAll(stdin)
	}
	if err != nil {
		return 2, err
	}
	e, err := agents.Save(*out, *id, string(content), *status, *reason)
	if err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 1, nil
	}
	fmt.Fprintf(stdout, "%s: %s · %d findings, %d leads · attempt %d", e.ID, e.Status, e.Findings, e.Leads, e.Attempts)
	if e.File != "" {
		fmt.Fprintf(stdout, " · %s", e.File)
	}
	fmt.Fprintln(stdout)
	return 0, nil
}
