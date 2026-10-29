package verifier

import (
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// Constant is one `uint256 constant NAME = VALUE;` of a verifier source.
type Constant struct {
	Name  string `json:"name"`
	Value string `json:"value"` // 0x-prefixed lower-case hex
	Line  int    `json:"line"`
	// VK marks verifying-key material (the template's VK points, public
	// input bases, SRS points, Pedersen keys), as opposed to template
	// constants (field moduli, precompile addresses, exponents).
	VK bool `json:"vk"`
}

var (
	reConst = regexp.MustCompile(`(?m)\buint(?:256)?\s+(?:(?:private|internal|public)\s+)?constant\s+([A-Za-z_]\w*)\s*=\s*(0[xX][0-9a-fA-F]+|\d+)\s*;`)
	// gnark Groth16 (ALPHA_X, BETA_NEG_X_0, ..., CONSTANT_X, PUB_3_Y,
	// PEDERSEN_G_X_0, PEDERSEN_GSIGMANEG_X_0), gnark PLONK (VK_*, G1_SRS_*,
	// G2_SRS_*, lower-case before v0.9.1), snarkjs (alphax, betax1, IC0x,
	// deltax1, gammax1, ...).
	reVKName = regexp.MustCompile(`^(ALPHA_|BETA_|GAMMA_|DELTA_|CONSTANT_|PUB_\d+_|PEDERSEN_|VK_|G1_SRS|G2_SRS|vk_|g1_srs|g2_srs|alpha[xy]|beta[xy]|gamma[xy]|delta[xy]|IC\d+[xy])`)
)

// Constants extracts the uint256 constants of a Solidity source.
func Constants(src string) []Constant {
	var out []Constant
	clean := stripLineComments(src)
	for _, m := range reConst.FindAllStringSubmatchIndex(clean, -1) {
		name := clean[m[2]:m[3]]
		v, ok := parseUint(clean[m[4]:m[5]])
		if !ok {
			continue
		}
		out = append(out, Constant{Name: name, Value: "0x" + v.Text(16), Line: 1 + strings.Count(clean[:m[0]], "\n"), VK: reVKName.MatchString(name)})
	}
	return out
}

func stripLineComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "//"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return strings.Join(lines, "\n")
}

func parseUint(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return new(big.Int).SetString(s[2:], 16)
	}
	return new(big.Int).SetString(s, 10)
}

// VKConstants returns only the verifying-key constants.
func VKConstants(src string) []Constant {
	var out []Constant
	for _, c := range Constants(src) {
		if c.VK {
			out = append(out, c)
		}
	}
	return out
}

// ConstantDiff compares two constant sets by name.
type ConstantDiff struct {
	Compared int      `json:"compared"`
	Equal    bool     `json:"equal"`
	Changed  []string `json:"changed,omitempty"`
	OnlyA    []string `json:"only_a,omitempty"`
	OnlyB    []string `json:"only_b,omitempty"`
}

func diffConstants(a, b []Constant) ConstantDiff {
	am, bm := map[string]string{}, map[string]string{}
	for _, c := range a {
		am[c.Name] = c.Value
	}
	for _, c := range b {
		bm[c.Name] = c.Value
	}
	d := ConstantDiff{}
	for n, v := range am {
		w, ok := bm[n]
		if !ok {
			d.OnlyA = append(d.OnlyA, n)
			continue
		}
		d.Compared++
		if v != w {
			d.Changed = append(d.Changed, n)
		}
	}
	for n := range bm {
		if _, ok := am[n]; !ok {
			d.OnlyB = append(d.OnlyB, n)
		}
	}
	sort.Strings(d.Changed)
	sort.Strings(d.OnlyA)
	sort.Strings(d.OnlyB)
	d.Equal = len(d.Changed) == 0 && len(d.OnlyA) == 0 && len(d.OnlyB) == 0
	return d
}
