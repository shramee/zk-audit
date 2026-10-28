package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
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
			// The Go tool lives inside the skill folder; its testdata (golden
			// reports, fixtures) is not documentation the model reads.
			if info.IsDir() && info.Name() == "tools" {
				return filepath.SkipDir
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
			p := filepath.Join(skill, "scripts", m[1])
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

// evalNames are identifiers of the eval fixtures. Hunting agents read the
// skill docs, so an example that uses them primes the agents toward the
// planted bugs and inflates eval recall.
var evalNames = []string{"TransferCircuit", "SigCircuit", "EdgeCircuit", "divHint", "splitHint", "transfer.go", "Pool.sol", "Pool.withdraw"}

func TestDocsDoNotNameEvalFixtures(t *testing.T) {
	for name, doc := range pluginDocs(t) {
		for _, id := range evalNames {
			if strings.Contains(doc, id) {
				t.Errorf("%s mentions %q from an eval fixture; use invented names in examples", name, id)
			}
		}
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

var (
	reSkillPath  = regexp.MustCompile(`\{skill\}/([A-Za-z0-9_./-]+)`)
	rePluginRoot = regexp.MustCompile(`\$\{CLAUDE_PLUGIN_ROOT\}(/[A-Za-z0-9_./-]*)?`)
)

// skillDocs returns the Markdown files inside the skill folder (SKILL.md,
// references/, agents/), keyed by their path relative to the skill.
func skillDocs(t *testing.T) map[string]string {
	t.Helper()
	docs := map[string]string{}
	err := filepath.Walk(skillRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == "tools" {
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(p, ".md") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(skillRoot, p)
			docs[rel] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := docs["SKILL.md"]; !ok || len(docs) < 10 {
		t.Fatalf("skill docs not found under %s (%d files)", skillRoot, len(docs))
	}
	return docs
}

// TestSkillIsSelfContained keeps the skill folder usable when it is copied
// alone into ~/.claude/skills/zk-audit: no file in it may reach outside
// {skill}, and every {skill}/<path> it names must exist inside it.
func TestSkillIsSelfContained(t *testing.T) {
	checked := 0
	for name, doc := range skillDocs(t) {
		if strings.Contains(doc, "{plugin}") {
			t.Errorf("%s uses {plugin}; the skill folder must not depend on the plugin root", name)
		}
		if strings.Contains(doc, "{skill}/..") {
			t.Errorf("%s resolves a path above {skill}", name)
		}
		for _, m := range rePluginRoot.FindAllStringSubmatch(doc, -1) {
			if m[1] != "/skills/zk-audit" {
				t.Errorf("%s names ${CLAUDE_PLUGIN_ROOT}%s; inside the skill use {skill}/... paths", name, m[1])
			}
		}
		for _, m := range reSkillPath.FindAllStringSubmatch(doc, -1) {
			p := strings.TrimRight(m[1], ".")
			if strings.Contains(p, "*") {
				continue
			}
			if _, err := os.Stat(filepath.Join(skillRoot, p)); err != nil {
				t.Errorf("%s names {skill}/%s, which does not exist in the skill folder", name, p)
			}
			checked++
		}
	}
	if checked < 10 {
		t.Fatalf("only %d {skill}/ paths checked; the pattern no longer matches the docs", checked)
	}
}

// TestCommandPathsExist checks every ${CLAUDE_PLUGIN_ROOT}/<path> a command
// names.
func TestCommandPathsExist(t *testing.T) {
	plugin := filepath.Join(repoRoot, "plugins", "zk-audit")
	cmds, _ := filepath.Glob(filepath.Join(plugin, "commands", "*.md"))
	checked := 0
	for _, c := range cmds {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rePluginRoot.FindAllStringSubmatch(string(b), -1) {
			p := strings.TrimRight(m[1], ".")
			if p == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(plugin, p)); err != nil {
				t.Errorf("%s names ${CLAUDE_PLUGIN_ROOT}%s, which does not exist", filepath.Base(c), p)
			}
			checked++
		}
	}
	if len(cmds) == 0 || checked < len(cmds) {
		t.Fatalf("%d commands, %d plugin paths checked", len(cmds), checked)
	}
}

// TestAgentBriefsInSync keeps the plugin's agent definitions identical to the
// briefs inside the skill folder, which a standalone install hands to a
// general-purpose agent. Run `make sync-agents` after editing the skill copy.
func TestAgentBriefsInSync(t *testing.T) {
	plugin := filepath.Join(repoRoot, "plugins", "zk-audit", "agents")
	skill := filepath.Join(skillRoot, "agents")
	names := map[string]bool{}
	for _, dir := range []string{plugin, skill} {
		m, _ := filepath.Glob(filepath.Join(dir, "*.md"))
		for _, p := range m {
			names[filepath.Base(p)] = true
		}
	}
	if len(names) == 0 {
		t.Fatal("no agent files found")
	}
	for n := range names {
		a, errA := os.ReadFile(filepath.Join(skill, n))
		b, errB := os.ReadFile(filepath.Join(plugin, n))
		switch {
		case errA != nil:
			t.Errorf("plugin agent %s has no brief in the skill folder (skills/zk-audit/agents/%s)", n, n)
		case errB != nil:
			t.Errorf("skill brief agents/%s has no plugin agent (plugins/zk-audit/agents/%s)", n, n)
		case !bytes.Equal(a, b):
			t.Errorf("agents/%s differs between the skill folder and the plugin; run `make sync-agents`", n)
		}
	}
}
