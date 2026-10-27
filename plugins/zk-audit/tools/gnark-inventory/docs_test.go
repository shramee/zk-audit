package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/validate"
)

var (
	reScript   = regexp.MustCompile(`\bscripts/([A-Za-z0-9_.-]+)`)
	reSubcmd   = regexp.MustCompile("(?:scripts/gnark-inventory|`gnark-inventory)[ \t]+([a-z][a-z-]*)([^`\n]*)")
	reFlag     = regexp.MustCompile(`(?:^|[\s\[(])--([a-z][a-z-]*)`)
	reRef      = regexp.MustCompile(`\breferences/([A-Za-z0-9_./-]+\.md)\b`)
	rePluginID = regexp.MustCompile(`\bzk-audit:([a-z][a-z-]*)\b`)
)

// pluginDocs returns every Markdown file the skill, commands and agents ship.
func pluginDocs(t *testing.T) map[string]string {
	t.Helper()
	plugin := filepath.Join(repoRoot, "plugins", "zk-audit")
	docs := map[string]string{}
	for _, dir := range []string{"skills", "commands", "agents"} {
		err := filepath.Walk(filepath.Join(plugin, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(p, ".md") {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(plugin, p)
				docs[rel] = string(b)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(plugin, "README.md")); err == nil {
		docs["README.md"] = string(b)
	}
	if len(docs) < 10 {
		t.Fatalf("only %d plugin docs found", len(docs))
	}
	return docs
}

// TestDocumentedCommandsExist fails when the skill, a command or an agent
// tells the model to run a script, subcommand, flag, validate kind, reference
// file or plugin agent that does not exist.
func TestDocumentedCommandsExist(t *testing.T) {
	plugin := filepath.Join(repoRoot, "plugins", "zk-audit")
	skill := filepath.Join(plugin, "skills", "zk-audit")
	checked := 0
	for name, doc := range pluginDocs(t) {
		for _, m := range reScript.FindAllStringSubmatch(doc, -1) {
			p := filepath.Join(plugin, "scripts", m[1])
			st, err := os.Stat(p)
			switch {
			case err != nil:
				t.Errorf("%s mentions scripts/%s, which does not exist", name, m[1])
			case st.Mode()&0o111 == 0:
				t.Errorf("%s mentions scripts/%s, which is not executable", name, m[1])
			}
			checked++
		}
		for _, m := range reSubcmd.FindAllStringSubmatch(doc, -1) {
			sub, rest := m[1], m[2]
			var stdout, stderr bytes.Buffer
			run([]string{sub, "-h"}, &stdout, &stderr)
			if strings.Contains(stderr.String(), errUnknown.Error()) {
				t.Errorf("%s runs `gnark-inventory %s`, which is not a subcommand", name, sub)
				continue
			}
			checked++
			if sub == "validate" {
				kind := strings.Fields(rest)
				if len(kind) == 0 {
					t.Errorf("%s runs `gnark-inventory validate` without a kind", name)
				} else if _, ok := validate.Kinds[kind[0]]; !ok && !strings.ContainsAny(kind[0], "|") {
					t.Errorf("%s runs `gnark-inventory validate %s`: unknown kind", name, kind[0])
				}
				continue
			}
			for _, f := range reFlag.FindAllStringSubmatch(rest, -1) {
				// Probe: set the flag, then -h stops before any work is done.
				stdout.Reset()
				stderr.Reset()
				run([]string{sub, "--" + f[1] + "=x", "-h"}, &stdout, &stderr)
				if strings.Contains(stderr.String(), "flag provided but not defined") {
					t.Errorf("%s runs `gnark-inventory %s --%s`: no such flag", name, sub, f[1])
				}
				checked++
			}
		}
		for _, m := range reRef.FindAllStringSubmatch(doc, -1) {
			if _, err := os.Stat(filepath.Join(skill, "references", m[1])); err != nil {
				t.Errorf("%s mentions references/%s, which does not exist", name, m[1])
			}
			checked++
		}
		for _, m := range rePluginID.FindAllStringSubmatch(doc, -1) {
			id := m[1]
			_, errA := os.Stat(filepath.Join(plugin, "agents", id+".md"))
			_, errC := os.Stat(filepath.Join(plugin, "commands", id+".md"))
			_, errS := os.Stat(filepath.Join(plugin, "skills", id, "SKILL.md"))
			if errA != nil && errC != nil && errS != nil {
				t.Errorf("%s mentions zk-audit:%s, which is no agent, command or skill of the plugin", name, id)
			}
			checked++
		}
	}
	if checked < 20 {
		t.Fatalf("only %d command references checked; the patterns no longer match the docs", checked)
	}
}

// TestDocsLintCatchesMistakes makes sure the patterns above fire.
func TestDocsLintCatchesMistakes(t *testing.T) {
	doc := "Run `{plugin}/scripts/gnark-inventory render --out x` and `gnark-inventory assemble --bogus y`."
	subs := reSubcmd.FindAllStringSubmatch(doc, -1)
	if len(subs) != 2 || subs[0][1] != "render" || subs[1][1] != "assemble" {
		t.Fatalf("subcommand pattern: %q", subs)
	}
	var o, e bytes.Buffer
	run([]string{"render", "-h"}, &o, &e)
	if !strings.Contains(e.String(), errUnknown.Error()) {
		t.Fatalf("unknown subcommand not reported: %s", e.String())
	}
	e.Reset()
	run([]string{"assemble", "--bogus=x", "-h"}, &o, &e)
	if !strings.Contains(e.String(), "flag provided but not defined") {
		t.Fatalf("unknown flag not reported: %s", e.String())
	}
	e.Reset()
	run([]string{"assemble", "--out=x", "-h"}, &o, &e)
	if strings.Contains(e.String(), "not defined") {
		t.Fatalf("known flag reported as unknown: %s", e.String())
	}
}
