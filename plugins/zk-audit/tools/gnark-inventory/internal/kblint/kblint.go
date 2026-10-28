// Package kblint lints the zk-audit knowledge base: attack-vector slices,
// the advisory table in gnark-versions.md, PoC template references and the
// reference links in SKILL.md. A lint that inspects zero vectors fails.
package kblint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/tools/gnark-inventory/internal/advisory"
)

// Report of a lint run.
type Report struct {
	Vectors  int
	Slices   int
	Files    int
	Errors   []string
	Warnings []string
}

// OK reports whether the lint passed.
func (r *Report) OK() bool { return len(r.Errors) == 0 }

func (r *Report) errf(format string, a ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, a...))
}
func (r *Report) warnf(format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
}

var (
	reVector   = regexp.MustCompile(`^\*\*(V-[A-Z]+[0-9]+)\. (.+)\*\*\s*$`)
	reField    = regexp.MustCompile(`^- \*\*(D|FP|Source|Seed|PoC):\*\*\s*(.*)$`)
	reURL      = regexp.MustCompile(`https://[^\s)>\]]+`)
	reGnarkSrc = regexp.MustCompile("`gnark/[A-Za-z0-9_./ -]+`")
	reTemplate = regexp.MustCompile(`\bT-[A-Z0-9]+(?:-[A-Z0-9]+)*\b`)
	reTmplHead = regexp.MustCompile(`^## (T-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b`)
	reFG       = regexp.MustCompile(`\bFG-[A-Z0-9-]+\b`)
	reRefPath  = regexp.MustCompile("`(references/[A-Za-z0-9_./*-]+)`")
	reManifest = regexp.MustCompile("^\\|\\s*`(?:attack-vectors/)?([a-z0-9-]+\\.md)`\\s*\\|.*\\|\\s*([0-9]+)\\s*\\|\\s*$")
)

// AllowedHosts are the source hosts a vector may cite. A citation outside
// this list is a lint error so new hosts are added deliberately.
var AllowedHosts = []string{
	"github.com", "reports.zksecurity.xyz", "blog.zksecurity.xyz", "leastauthority.com",
	"www.openzeppelin.com", "eprint.iacr.org", "nvd.nist.gov", "pkg.go.dev", "ethresear.ch",
	"api.osv.dev", "osv.dev", "www.usenix.org", "docs.zkao.io", "zkao.io", "blog.trailofbits.com",
	"zellic.io", "veridise.com", "github.com/0xPARC", "arxiv.org", "docs.gnark.consensys.io",
}

// Options for Lint.
type Options struct {
	// GnarkSrc, when set, is a gnark checkout; every `gnark/<path>` cited in a
	// Source: field must exist in it.
	GnarkSrc string
}

// Lint checks the skill directory (the one holding SKILL.md).
func Lint(skillDir string, ruleIDs map[string]bool, opts ...Options) (*Report, error) {
	r := &Report{}
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	refs := filepath.Join(skillDir, "references")
	templates, err := templateIDs(filepath.Join(refs, "poc-templates.md"))
	if err != nil {
		r.errf("poc-templates.md: %v", err)
	}
	if len(templates) == 0 {
		r.errf("poc-templates.md: no `## T-...` templates found")
	}
	slices, err := filepath.Glob(filepath.Join(refs, "attack-vectors", "*.md"))
	if err != nil {
		return nil, err
	}
	sort.Strings(slices)
	ids := map[string]string{}
	perSlice := map[string]int{}
	for _, s := range slices {
		if filepath.Base(s) == "index.md" {
			continue
		}
		r.Slices++
		n, err := lintSlice(r, s, ids, templates, ruleIDs, opt)
		if err != nil {
			return nil, err
		}
		perSlice[filepath.Base(s)] = n
		if n == 0 {
			r.errf("%s: no vectors", filepath.Base(s))
		}
	}
	if r.Vectors == 0 {
		r.errf("zero vectors inspected under %s", filepath.Join(refs, "attack-vectors"))
	}
	lintManifest(r, filepath.Join(refs, "attack-vectors", "index.md"), perSlice)
	lintVersions(r, filepath.Join(refs, "gnark-versions.md"))
	lintSkill(r, skillDir)
	return r, nil
}

func templateIDs(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if m := reTmplHead.FindStringSubmatch(sc.Text()); m != nil {
			out[m[1]] = true
		}
	}
	return out, sc.Err()
}

type vector struct {
	id, title string
	line      int
	fields    map[string]string
}

func lintSlice(r *Report, path string, ids map[string]string, templates, rules map[string]bool, opt Options) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	r.Files++
	base := filepath.Base(path)
	var vs []*vector
	var cur *vector
	lines := strings.Split(string(b), "\n")
	for i, ln := range lines {
		if m := reVector.FindStringSubmatch(ln); m != nil {
			cur = &vector{id: m[1], title: m[2], line: i + 1, fields: map[string]string{}}
			vs = append(vs, cur)
			continue
		}
		if strings.HasPrefix(ln, "#") {
			cur = nil
			continue
		}
		if cur == nil {
			if strings.HasPrefix(strings.TrimSpace(ln), "**V-") {
				r.errf("%s:%d: malformed vector header %q (want **V-XX. Title**)", base, i+1, strings.TrimSpace(ln))
			}
			continue
		}
		if m := reField.FindStringSubmatch(ln); m != nil {
			if _, dup := cur.fields[m[1]]; dup {
				r.errf("%s:%d: %s has a duplicate %s field", base, i+1, cur.id, m[1])
			}
			cur.fields[m[1]] = strings.TrimSpace(m[2])
		}
	}
	for _, v := range vs {
		at := fmt.Sprintf("%s:%d %s", base, v.line, v.id)
		r.Vectors++
		if prev, ok := ids[v.id]; ok {
			r.errf("%s: duplicate id (also in %s)", at, prev)
		}
		ids[v.id] = base
		for _, f := range []string{"D", "FP", "Source", "Seed", "PoC"} {
			if strings.TrimSpace(v.fields[f]) == "" {
				r.errf("%s: missing or empty %s:", at, f)
			}
		}
		for f, val := range v.fields {
			l := strings.ToLower(val)
			if strings.Contains(l, "todo") || strings.Contains(l, "tbd") || strings.Contains(l, "example.com") || strings.Contains(l, "lorem") {
				r.errf("%s: placeholder text in %s:", at, f)
			}
		}
		lintSource(r, at, v.fields["Source"], opt)
		lintSeed(r, at, v.fields["Seed"], rules)
		lintPoC(r, at, v.fields["PoC"], templates)
	}
	return len(vs), nil
}

func lintSource(r *Report, at, src string, opt Options) {
	if src == "" {
		return
	}
	urls := reURL.FindAllString(src, -1)
	paths := reGnarkSrc.FindAllString(src, -1)
	if opt.GnarkSrc != "" {
		for _, p := range paths {
			rel := strings.TrimPrefix(strings.Trim(p, "`"), "gnark/")
			if _, err := os.Stat(filepath.Join(opt.GnarkSrc, rel)); err != nil {
				r.errf("%s: Source: %s does not exist in %s", at, p, opt.GnarkSrc)
			}
		}
	}
	if len(urls) == 0 && len(paths) == 0 {
		r.errf("%s: Source: needs at least one https URL or a `gnark/<path>` source reference", at)
	}
	for _, u := range urls {
		host := strings.TrimPrefix(u, "https://")
		ok := false
		for _, h := range AllowedHosts {
			if strings.HasPrefix(host, h+"/") || host == h || strings.HasPrefix(host, h) && strings.Contains(h, "/") {
				ok = true
			}
		}
		if !ok {
			r.errf("%s: Source: host of %s is not in the allowed list (kblint.AllowedHosts)", at, u)
		}
	}
}

func lintSeed(r *Report, at, seed string, rules map[string]bool) {
	if seed == "" {
		return
	}
	ok := false
	for _, id := range reFG.FindAllString(seed, -1) {
		if !rules[id] {
			r.errf("%s: Seed: unknown inventory rule %s", at, id)
		} else {
			ok = true
		}
	}
	if strings.Contains(seed, "grep:") || strings.Contains(seed, "manual") || strings.Contains(seed, "inventory:") {
		ok = true
	}
	if !ok {
		r.errf("%s: Seed: needs an FG-* rule id, `grep:` pattern, `inventory:` field or `manual`", at)
	}
}

func lintPoC(r *Report, at, poc string, templates map[string]bool) {
	if poc == "" {
		return
	}
	found := reTemplate.FindAllString(poc, -1)
	if len(found) == 0 {
		r.errf("%s: PoC: must name a template (T-...) from poc-templates.md", at)
	}
	for _, t := range found {
		if !templates[t] {
			r.errf("%s: PoC: unknown template %s", at, t)
		}
	}
}

func lintManifest(r *Report, path string, perSlice map[string]int) {
	b, err := os.ReadFile(path)
	if err != nil {
		r.errf("attack-vectors/index.md: %v", err)
		return
	}
	r.Files++
	listed := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		m := reManifest.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		listed[m[1]] = true
		n, _ := strconv.Atoi(m[2])
		got, ok := perSlice[m[1]]
		if !ok {
			r.errf("index.md lists %s, which does not exist", m[1])
			continue
		}
		if got != n {
			r.errf("index.md says %s has %d vectors, it has %d", m[1], n, got)
		}
	}
	for s := range perSlice {
		if !listed[s] {
			r.errf("index.md does not list slice %s", s)
		}
	}
}

// VersionsBlock extracts the fenced ```json block of gnark-versions.md.
func VersionsBlock(md []byte) ([]byte, error) {
	s := string(md)
	start := strings.Index(s, "```json\n")
	if start < 0 {
		return nil, fmt.Errorf("no ```json block")
	}
	rest := s[start+len("```json\n"):]
	end := strings.Index(rest, "\n```")
	if end < 0 {
		return nil, fmt.Errorf("unterminated ```json block")
	}
	return []byte(rest[:end+1]), nil
}

// SameJSON reports whether two JSON documents are semantically equal.
func SameJSON(a, b []byte) (bool, error) {
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false, err
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return bytes.Equal(ja, jb), nil
}

func lintVersions(r *Report, path string) {
	md, err := os.ReadFile(path)
	if err != nil {
		r.errf("gnark-versions.md: %v", err)
		return
	}
	r.Files++
	block, err := VersionsBlock(md)
	if err != nil {
		r.errf("gnark-versions.md: %v", err)
		return
	}
	same, err := SameJSON(block, advisory.Raw())
	if err != nil {
		r.errf("gnark-versions.md: json block: %v", err)
		return
	}
	if !same {
		r.errf("gnark-versions.md: json block differs from the tool's embedded advisories.json; keep them identical")
	}
	tab, err := advisory.Load()
	if err != nil {
		r.errf("advisories.json: %v", err)
		return
	}
	table := string(md[:bytes.Index(md, []byte("```json"))])
	for _, a := range tab.Advisories {
		if !strings.Contains(table, a.ID) {
			r.errf("gnark-versions.md: advisory %s missing from the human-readable table", a.ID)
		}
	}
}

func lintSkill(r *Report, skillDir string) {
	p := filepath.Join(skillDir, "SKILL.md")
	b, err := os.ReadFile(p)
	if err != nil {
		r.errf("SKILL.md: %v", err)
		return
	}
	r.Files++
	if n := bytes.Count(b, []byte("\n")); n >= 500 {
		r.errf("SKILL.md has %d lines; keep it under 500", n)
	}
	if !bytes.HasPrefix(b, []byte("---\n")) {
		r.errf("SKILL.md: missing frontmatter")
	}
	seenRef := map[string]bool{}
	for _, m := range reRefPath.FindAllStringSubmatch(string(b), -1) {
		ref := m[1]
		if seenRef[ref] {
			continue
		}
		seenRef[ref] = true
		if strings.Contains(ref, "*") {
			matches, _ := filepath.Glob(filepath.Join(skillDir, ref))
			if len(matches) == 0 {
				r.errf("SKILL.md references %s, which matches nothing", ref)
			}
			continue
		}
		if strings.Count(ref, "/") > 2 {
			r.errf("SKILL.md references %s, deeper than one level below references/", ref)
		}
		if _, err := os.Stat(filepath.Join(skillDir, ref)); err != nil {
			r.errf("SKILL.md references %s, which does not exist", ref)
		}
	}
}
