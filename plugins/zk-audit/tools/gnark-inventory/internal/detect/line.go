package detect

import (
	"fmt"
	"strings"
)

// Line is the one-line stack banner the skill prints after Phase 0. The
// report's scope table prints the same line.
func (st *Stack) Line() string {
	var parts []string
	if st.Gnark.Present {
		parts = append(parts, fmt.Sprintf("gnark %s (advisories: %d)", strings.Join(st.Gnark.Versions, ","), len(st.Gnark.Advisories)))
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
