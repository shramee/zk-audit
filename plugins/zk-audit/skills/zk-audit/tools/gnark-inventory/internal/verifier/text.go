package verifier

import (
	"fmt"
	"strings"
)

// Provenance is the static provenance section of inventory.json: the ABI
// check and the ceremony scan, which need no network, no user artefact and
// no target code execution.
type Provenance struct {
	ABI      *ABIReport `json:"abi"`
	Ceremony *Ceremony  `json:"ceremony"`
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}

// ABIText renders an ABI report as Markdown.
func ABIText(r *ABIReport, g Gnark) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	pinned := "none found"
	if len(g.Versions) > 0 {
		pinned = strings.Join(g.Versions, ", ")
	}
	w("Pinned gnark: %s; backends: %s.\n\n", pinned, strings.Join(g.Backends, ", "))
	if len(r.Calls) == 0 {
		w("No external verification call to check.\n\n")
	} else {
		w("| Call site | Caller | Caller sends | Decodes | Against | Expected | Status | Detail |\n|---|---|---|---|---|---|---|---|\n")
		for _, c := range r.Calls {
			sent := c.Signature
			if sent == "" {
				sent = c.Callee + "(?)"
			}
			if c.Selector != "" {
				sent += " " + c.Selector
			}
			dec := strings.Join(c.Returns, ",")
			if dec == "" {
				dec = "nothing"
			}
			if len(c.Against) == 0 {
				w("| %s | `%s` | `%s` | %s | – | – | unknown | no verifier in the repository and no pinned gnark version to compare with |\n", c.Site, c.Caller, cell(sent), dec)
				continue
			}
			for _, a := range c.Against {
				exp := a.Signature
				if a.Selector != "" {
					exp += " " + a.Selector
				}
				w("| %s | `%s` | `%s` | %s | %s | `%s` | **%s** | %s |\n", c.Site, c.Caller, cell(sent), dec, cell(a.Name), cell(exp), a.Status, cell(a.Detail))
			}
		}
		w("\n")
	}
	if len(r.Verifiers) > 0 {
		w("| Verifier | Site | Kind | Template | Against | Status | Detail |\n|---|---|---|---|---|---|---|\n")
		for _, v := range r.Verifiers {
			w("| `%s` | %s | %s | %s | %s | **%s** | %s |\n", v.Verifier, v.Site, v.Kind, cell(v.Template), v.Pinned, v.Status, cell(v.Detail))
		}
		w("\n")
	}
	return b.String()
}

// DiffText renders a diff report.
func DiffText(d *DiffReport) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	for _, s := range d.Sides {
		w("%s: %s %s, %d public inputs, commitments %v, %d VK constants\n", s.Name, or(s.Kind, "not a recognised verifier"), s.Contract, s.NbPublic, s.Commit, s.VKCount)
	}
	if d.Structure.Equal {
		w("structure: equal\n")
	} else {
		w("structure: differs\n")
		for _, x := range d.Structure.Differences {
			w("  - %s\n", x)
		}
	}
	switch {
	case d.VK.Equal && d.VK.Compared > 0:
		w("vk: equal (%d constants)\n", d.VK.Compared)
	case d.VK.Equal:
		w("vk: no named VK constants on either side\n")
	default:
		w("vk: differs (changed %d, only in a %d, only in b %d of %d compared)\n", len(d.VK.Changed), len(d.VK.OnlyA), len(d.VK.OnlyB), d.VK.Compared)
	}
	w("summary: %s\n", d.Summary)
	return b.String()
}

// CeremonyText renders a ceremony scan.
func CeremonyText(c *Ceremony) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("Setup provenance: **%s**. %s.\n\n", c.Verdict, capFirst(c.Detail))
	if len(c.Setups) > 0 {
		w("| Call | Site | Kind | In test |\n|---|---|---|---|\n")
		for _, s := range c.Setups {
			w("| `%s` | %s:%d | %s | %v |\n", cell(s.Call), s.File, s.Line, s.Kind, s.InTest)
		}
		w("\n")
	}
	if len(c.Artifacts) > 0 {
		w("| File | Kind | Size | Contributions | SHA-256 |\n|---|---|---|---|---|\n")
		for _, a := range c.Artifacts {
			n := "not recorded"
			if a.Contributions >= 0 {
				n = fmt.Sprint(a.Contributions)
			}
			w("| %s | %s | %d | %s | `%s` |\n", a.File, a.Kind, a.Size, n, a.SHA256)
		}
		w("\n")
	}
	return b.String()
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
