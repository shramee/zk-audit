package verifier

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
)

// Side summarises one verifier source.
type Side struct {
	Name      string   `json:"name"`
	Contract  string   `json:"contract,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Template  string   `json:"template,omitempty"`
	Pragma    string   `json:"pragma,omitempty"`
	NbPublic  int      `json:"nb_public"`
	Commit    bool     `json:"commitments"`
	Functions []string `json:"functions"`
	VKCount   int      `json:"vk_constants"`
}

// DiffReport compares two verifier sources: their structure (template,
// function shapes, public-input count, commitment support, template
// constants, the code with VK values masked) and, separately, their
// verifying-key constants. A verifier regenerated from a fresh setup has
// the committed one's structure and different VK constants; equal VK
// constants need the same keys (the user's vk file or ceremony output).
type DiffReport struct {
	A, B      Side         `json:"-"`
	Sides     []Side       `json:"sides"`
	Structure StructDiff   `json:"structure"`
	VK        ConstantDiff `json:"vk"`
	Summary   string       `json:"summary"`
}

// StructDiff lists structural differences.
type StructDiff struct {
	Equal       bool         `json:"equal"`
	Differences []string     `json:"differences,omitempty"`
	Constants   ConstantDiff `json:"template_constants"`
	// CodeEqual reports whether the sources are equal once comments,
	// whitespace and VK constant values are removed.
	CodeEqual bool `json:"code_equal_without_vk"`
	// FirstDiff is the first differing normalised line pair.
	FirstDiff []string `json:"first_code_difference,omitempty"`
}

var rePragma = regexp.MustCompile(`pragma\s+solidity\s+([^;]+);`)

func side(name, src string) (Side, *solidity.Result) {
	r := solidity.ScanSource(name, src)
	s := Side{Name: name, NbPublic: -1, Functions: []string{}}
	if m := rePragma.FindStringSubmatch(src); m != nil {
		s.Pragma = strings.TrimSpace(m[1])
	}
	if len(r.Verifiers) > 0 {
		v := r.Verifiers[0]
		s.Contract, s.Kind, s.Template, s.NbPublic, s.Commit = v.Contract, v.Kind, v.Template, v.NbPublic, v.Commitments
		if c, ok := r.ContractByName(v.Contract); ok {
			for _, f := range c.Functions {
				if f.Visibility == "public" || f.Visibility == "external" {
					sig := f.Signature
					if sig == "" {
						sig = f.Name + "(?)"
					}
					var rets []string
					for _, p := range f.Returns {
						rets = append(rets, p.Type)
					}
					if len(rets) > 0 {
						sig += " returns (" + strings.Join(rets, ",") + ")"
					}
					s.Functions = append(s.Functions, sig)
				}
			}
			sort.Strings(s.Functions)
		}
	}
	s.VKCount = len(VKConstants(src))
	return s, r
}

// Diff compares verifier source a with b.
func Diff(nameA, srcA, nameB, srcB string) *DiffReport {
	a, _ := side(nameA, srcA)
	b, _ := side(nameB, srcB)
	d := &DiffReport{A: a, B: b, Sides: []Side{a, b}}
	sd := &d.Structure
	add := func(f string, x ...any) { sd.Differences = append(sd.Differences, fmt.Sprintf(f, x...)) }
	if a.Kind != b.Kind {
		add("kind: %s vs %s", or(a.Kind, "not a verifier"), or(b.Kind, "not a verifier"))
	}
	if a.Template != b.Template {
		add("template: %q vs %q", a.Template, b.Template)
	}
	if a.NbPublic != b.NbPublic {
		add("public inputs: %d vs %d", a.NbPublic, b.NbPublic)
	}
	if a.Commit != b.Commit {
		add("commitment support: %v vs %v", a.Commit, b.Commit)
	}
	if a.Pragma != b.Pragma {
		add("pragma: %s vs %s", a.Pragma, b.Pragma)
	}
	fa, fb := strings.Join(a.Functions, "; "), strings.Join(b.Functions, "; ")
	if fa != fb {
		add("public functions: [%s] vs [%s]", fa, fb)
	}
	var ta, tb []Constant
	for _, c := range Constants(srcA) {
		if !c.VK {
			ta = append(ta, c)
		}
	}
	for _, c := range Constants(srcB) {
		if !c.VK {
			tb = append(tb, c)
		}
	}
	sd.Constants = diffConstants(ta, tb)
	if !sd.Constants.Equal {
		add("template constants differ: changed %v, only in %s %v, only in %s %v", sd.Constants.Changed, nameA, sd.Constants.OnlyA, nameB, sd.Constants.OnlyB)
	}
	na, nb := normalise(srcA), normalise(srcB)
	sd.CodeEqual = strings.Join(na, "\n") == strings.Join(nb, "\n")
	if !sd.CodeEqual {
		for i := 0; i < len(na) || i < len(nb); i++ {
			x, y := line(na, i), line(nb, i)
			if x != y {
				sd.FirstDiff = []string{x, y}
				break
			}
		}
		add("code differs with VK values masked (first difference: %q vs %q)", sd.FirstDiff[0], sd.FirstDiff[1])
	}
	sd.Equal = len(sd.Differences) == 0
	d.VK = diffConstants(VKConstants(srcA), VKConstants(srcB))
	switch {
	case sd.Equal && d.VK.Equal:
		d.Summary = "same structure and same verifying key: the two sources are the same verifier"
	case sd.Equal:
		d.Summary = fmt.Sprintf("same structure, different verifying key (%d of %d VK constants differ): expected for a fresh setup; equal keys need the deployed vk file or ceremony output", len(d.VK.Changed)+len(d.VK.OnlyA)+len(d.VK.OnlyB), d.VK.Compared+len(d.VK.OnlyA)+len(d.VK.OnlyB))
	case d.VK.Equal && d.VK.Compared > 0:
		d.Summary = "same verifying key, different structure: the template, options or a hand edit differ"
	default:
		d.Summary = "different structure and different verifying key"
	}
	return d
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func line(xs []string, i int) string {
	if i < len(xs) {
		return xs[i]
	}
	return "<end>"
}

var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reSpace        = regexp.MustCompile(`\s+`)
)

// normalise removes comments and blank lines, collapses whitespace and
// masks VK constant values, so two sources from the same template and
// options compare equal whatever their keys.
func normalise(src string) []string {
	s := reBlockComment.ReplaceAllString(src, "")
	s = stripLineComments(s)
	vk := map[string]bool{}
	for _, c := range VKConstants(src) {
		vk[c.Name] = true
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(reSpace.ReplaceAllString(l, " "))
		if l == "" {
			continue
		}
		if m := reConst.FindStringSubmatch(l); m != nil && vk[m[1]] {
			l = strings.Replace(l, m[2], "<vk>", 1)
		}
		out = append(out, l)
	}
	return out
}
