package harness

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
)

func TestQualify(t *testing.T) {
	for in, want := range map[string]string{
		"*Accumulator":                 "*lib.Accumulator",
		"frontend.Variable":            "frontend.Variable",
		"[]Point":                      "[]lib.Point",
		"emulated.Element[T]":          "emulated.Element[lib.T]",
		"map[string]frontend.Variable": "map[string]frontend.Variable",
	} {
		if got := qualify(in, "lib"); got != want {
			t.Errorf("qualify(%q) = %q, want %q", in, got, want)
		}
	}
	if got := typeParams("func Canonical[T emulated.FieldParams](f *emulated.Field[T])"); len(got) != 1 || got[0] != "T" {
		t.Errorf("typeParams = %v", got)
	}
}

// TestGenerateExternalMethod: a method gadget in external mode imports the
// package, qualifies the receiver's constructor and parses.
func TestGenerateExternalMethod(t *testing.T) {
	inv := &inventory.Inventory{Gadgets: []*inventory.Gadget{
		{Name: "lib.NewCounter", Params: []*inventory.GadgetParam{{Name: "api", Kind: "api", Type: "frontend.API"}}},
	}}
	g := &inventory.Gadget{Name: "lib.Counter.Inc", ImportPath: "example.com/lib", Receiver: "Counter", Signature: "func (c *Counter) Inc(v frontend.Variable, opts ...Option) frontend.Variable",
		Params:  []*inventory.GadgetParam{{Name: "v", Kind: "variable", Type: "frontend.Variable"}, {Name: "opts", Kind: "other", Type: "...Option"}},
		Results: []*inventory.GadgetResult{{Index: 0, Type: "frontend.Variable"}}, HintIDs: []string{"H1"}}
	inv.Hints = []*inventory.HintSite{{ID: "H1", HintFunc: "incHint"}}
	src, err := Generate(inv, g, Options{External: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "h.go", src, 0); err != nil {
		t.Fatalf("does not parse: %v\n%s", err, src)
	}
	for _, want := range []string{"package lib_test", `"example.com/lib"`, "obj := lib.NewCounter(api)", "out0 := obj.Inc(c.V)", "the variadic opts", "var id solver.HintID // TODO: incHint is not in this package"} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q in\n%s", want, src)
		}
	}
	if FileName(g) != "zkaudit_harness_counterinc_test.go" {
		t.Errorf("file name %s", FileName(g))
	}
}
