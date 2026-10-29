package inventory

import (
	"sort"
	"strings"
	"testing"
)

// TestGadgetInventory checks the exported-gadget inventory of the
// lib-gadgets fixture in both load modes: the same gadgets, input flows,
// result sources and doc checks.
func TestGadgetInventory(t *testing.T) {
	for _, syntax := range []bool{false, true} {
		inv := build(t, "lib-gadgets", syntax)
		mode := map[bool]string{false: "types", true: "syntax"}[syntax]
		by := map[string]*Gadget{}
		var names []string
		for _, g := range inv.Gadgets {
			by[g.Name] = g
			names = append(names, g.Name)
		}
		sort.Strings(names)
		want := "gadgets.Accumulator.Add,gadgets.Accumulator.AssertCountAtMost,gadgets.AssertRange,gadgets.Canonical,gadgets.DivMod,gadgets.IsLess,gadgets.Mux3,gadgets.NewAccumulator,gadgets.ToBits"
		if strings.Join(names, ",") != want {
			t.Fatalf("%s: gadgets %v", mode, names)
		}
		if inv.Summary.Gadgets != 9 {
			t.Errorf("%s: summary gadgets %d", mode, inv.Summary.Gadgets)
		}
		checks := func(name string) string {
			var ks []string
			for _, c := range by[name].Checks {
				ks = append(ks, c.Kind)
			}
			return strings.Join(ks, ",")
		}
		flows := func(name string) string {
			var fs []string
			for _, p := range by[name].Params {
				fs = append(fs, p.Name+":"+p.Flow)
			}
			return strings.Join(fs, ",")
		}
		for name, want := range map[string]string{
			// planted: the doc promises what no constraint enforces
			"gadgets.ToBits":    "promise-boolean,promise-range",
			"gadgets.DivMod":    "promise-range",
			"gadgets.Canonical": "promise-range,promise-canonical",
			// controls
			"gadgets.AssertRange":                   "",
			"gadgets.IsLess":                        "",
			"gadgets.Accumulator.Add":               "",
			"gadgets.Accumulator.AssertCountAtMost": "",
		} {
			if got := checks(name); got != want {
				t.Errorf("%s: %s checks %q, want %q", mode, name, got, want)
			}
		}
		for name, want := range map[string]string{
			"gadgets.ToBits":          "api:–,v:constrained,nbBits:compile-time",
			"gadgets.DivMod":          "api:–,a:constrained,b:constrained",
			"gadgets.Mux3":            "api:–,sel:constrained,in:escapes",
			"gadgets.Canonical":       "f:–,x:escapes",
			"gadgets.Accumulator.Add": "v:escapes",
		} {
			if got := flows(name); got != want {
				t.Errorf("%s: %s flows %q, want %q", mode, name, got, want)
			}
		}
		// ToBits reaches its constraint only through the unexported helper
		tb := by["gadgets.ToBits"]
		if strings.Join(tb.Followed, ",") != "recompose" || len(tb.HintIDs) != 1 || len(tb.Results) != 1 || tb.Results[0].Source != "hint" ||
			!strings.HasSuffix(tb.Results[0].Hints[0], " reached") {
			t.Errorf("%s: ToBits followed %v hints %v results %+v", mode, tb.Followed, tb.HintIDs, tb.Results[0])
		}
		dm := by["gadgets.DivMod"]
		if len(dm.Results) != 2 || dm.Results[1].Name != "r" || dm.Results[1].Source != "hint" {
			t.Errorf("%s: DivMod results %+v", mode, dm.Results)
		}
		if len(dm.Preconds) != 1 || !strings.Contains(dm.Preconds[0].Text, "caller must range-check") {
			t.Errorf("%s: DivMod preconditions %+v", mode, dm.Preconds)
		}
		if add := by["gadgets.Accumulator.Add"]; add.Receiver != "Accumulator" || len(add.Preconds) != 1 || add.Preconds[0].Kinds[0] != "boolean" {
			t.Errorf("%s: Accumulator.Add %+v", mode, add)
		}
		if c := by["gadgets.Canonical"]; !strings.Contains(c.Signature, "Canonical[T emulated.FieldParams](f *emulated.Field[T]") {
			t.Errorf("%s: Canonical signature %q", mode, c.Signature)
		}
	}
}

func TestClassifyDoc(t *testing.T) {
	prom, pre := classifyDoc("Foo returns the bits of x. The caller must ensure x is nonzero; Foo asserts the result is on the curve.")
	if len(prom) != 2 || len(pre) != 1 {
		t.Fatalf("promises %+v preconditions %+v", prom, pre)
	}
	if prom[0].Kinds[0] != "boolean" || prom[1].Kinds[0] != "on-curve" || pre[0].Kinds[0] != "nonzero" {
		t.Errorf("kinds: %+v %+v", prom, pre)
	}
}
