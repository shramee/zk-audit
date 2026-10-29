package detect

import (
	"fmt"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/advisory"
)

// Line is the one-line stack banner the skill prints after Phase 0. The
// report's scope table prints the same line.
func (st *Stack) Line() string {
	var parts []string
	if st.Gnark.Present {
		g, c := 0, 0
		for _, a := range st.Gnark.Advisories {
			if a.Package == advisory.GnarkCrypto {
				c++
			} else {
				g++
			}
		}
		parts = append(parts, fmt.Sprintf("gnark %s (advisories: %d)", strings.Join(st.Gnark.Versions, ","), g))
		if cv := st.cryptoVersions(); len(cv) > 0 {
			parts = append(parts, fmt.Sprintf("gnark-crypto %s (advisories: %d)", strings.Join(cv, ","), c))
		}
	} else {
		parts = append(parts, "gnark: no")
	}
	if len(st.Gnark.Backends) > 0 {
		parts = append(parts, strings.Join(st.Gnark.Backends, "/"))
	}
	if len(st.Gnark.Curves) > 0 {
		parts = append(parts, strings.Join(st.Gnark.Curves, ","))
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	parts = append(parts, "solidity: "+yes(st.Solidity.Present), "foundry: "+yes(st.Foundry.Present))
	if st.Circom.Present {
		parts = append(parts, "circom: yes")
	}
	if st.Noir.Present {
		parts = append(parts, "noir: yes")
	}
	return strings.Join(parts, " · ")
}

// cryptoVersions lists the distinct gnark-crypto versions pinned across
// go.mod files, in file order.
func (st *Stack) cryptoVersions() []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range st.GoModules {
		if m.GnarkCrypto != "" && !seen[m.GnarkCrypto] {
			seen[m.GnarkCrypto] = true
			out = append(out, m.GnarkCrypto)
		}
	}
	return out
}
