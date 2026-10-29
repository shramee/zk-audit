package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	profiles "github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// cmdProfiles prints the lens, critic and profile definitions, or checks /
// rewrites the generated tables in the skill docs.
func cmdProfiles(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("profiles", flag.ContinueOnError)
	only := fs.String("profile", "", "print one profile with its selected lenses and critics")
	md := fs.Bool("markdown", false, "print the generated Markdown tables instead of JSON")
	check := fs.String("check-docs", "", "exit 1 when a generated table in this skill directory differs from profiles.json")
	sync := fs.String("sync-docs", "", "rewrite the generated tables in this skill directory")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	set := profiles.Load()
	switch {
	case *sync != "" || *check != "":
		dir := *sync
		if dir == "" {
			dir = *check
		}
		drift, err := set.SyncDocs(dir, *sync != "")
		if err != nil {
			return 2, err
		}
		if missing := set.CheckFiles(dir); len(missing) > 0 {
			for _, m := range missing {
				fmt.Fprintln(stdout, "error:", m)
			}
			return 1, nil
		}
		if len(drift) == 0 {
			fmt.Fprintln(stdout, "OK generated tables match profiles.json")
			return 0, nil
		}
		verb := "rewrote"
		if *sync == "" {
			verb = "out of date (run make sync-profiles):"
		}
		fmt.Fprintf(stdout, "%s %s\n", verb, strings.Join(drift, ", "))
		if *sync == "" {
			return 1, nil
		}
		return 0, nil
	case *md:
		fmt.Fprintln(stdout, set.ProfileTable())
		fmt.Fprint(stdout, set.AgentTable())
		return 0, nil
	case *only != "":
		p, ok := set.Profile(*only)
		if !ok {
			return 2, fmt.Errorf("profiles: unknown profile %q (want one of %s)", *only, strings.Join(set.ProfileIDs(), ", "))
		}
		var critics []profiles.Critic
		for _, id := range p.Critics {
			for _, c := range set.Critics {
				if c.ID == id {
					critics = append(critics, c)
				}
			}
		}
		return 0, writeJSON(stdout, struct {
			Profile *profiles.Profile `json:"profile"`
			Lenses  []profiles.Lens   `json:"lenses"`
			Critics []profiles.Critic `json:"critics"`
		}{p, set.LensesFor(p.ID), critics})
	}
	_, err := stdout.Write(profiles.Raw())
	return 0, err
}
