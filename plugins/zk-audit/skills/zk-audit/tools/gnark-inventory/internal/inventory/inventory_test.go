package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
)

func build(t *testing.T, fixture string, syntax bool) *Inventory {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", fixture)
	prog, err := load.Load(root, load.Options{SyntaxOnly: syntax})
	if err != nil {
		t.Fatal(err)
	}
	if !syntax && prog.Mode != "types" {
		if os.Getenv("ZK_INVENTORY_REQUIRE_TYPES") != "" {
			t.Fatalf("type loading failed for %s (mode %s): %v", fixture, prog.Mode, prog.Errors)
		}
		t.Skipf("type loading unavailable for %s (run `make fixtures` to download gnark into the module cache): %v", fixture, prog.Errors)
	}
	inv, err := Build(prog, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// leafNames expands groups into gnark leaf names, as frontend/schema names
// them (arrays of variables get _<i> suffixes).
func leafNames(gs []*Group) []string {
	var out []string
	for _, g := range gs {
		if g.Kind == "array" && g.Len > 1 && !strings.Contains(g.Name, "{i}") {
			for i := 0; i < g.Len; i++ {
				out = append(out, g.Name+"_"+strconv.Itoa(i))
			}
			continue
		}
		out = append(out, g.Name)
	}
	return out
}

func circuit(t *testing.T, inv *Inventory, name string) *Circuit {
	t.Helper()
	for _, c := range inv.Circuits {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("circuit %s not found", name)
	return nil
}

func modes() []struct {
	name   string
	syntax bool
} {
	return []struct {
		name   string
		syntax bool
	}{{"types", false}, {"syntax", true}}
}

// Expected layouts below were produced by gnark v0.14.0 frontend/schema.Walk
// on the fixture circuits (TransferCircuit with len(Extra) = 2).
func TestPoolWitnessOrder(t *testing.T) {
	for _, m := range modes() {
		t.Run(m.name, func(t *testing.T) {
			inv := build(t, "pool", m.syntax)
			if len(inv.Circuits) != 3 {
				t.Fatalf("want 3 circuits, got %d", len(inv.Circuits))
			}
			tr := circuit(t, inv, "TransferCircuit")
			if !tr.Witness.Resolved || tr.Witness.Source != m.name {
				t.Fatalf("resolved=%v source=%s", tr.Witness.Resolved, tr.Witness.Source)
			}
			wantPub := []string{"Root", "nf", "Recipient", "Fees_0", "Fees_1", "Out_Value", "Out_Owner"}
			if got := leafNames(tr.Witness.Public); !reflect.DeepEqual(got, wantPub) {
				t.Errorf("public order\n got %v\nwant %v", got, wantPub)
			}
			if tr.Witness.NbPublic != 7 {
				t.Errorf("nb_public %d", tr.Witness.NbPublic)
			}
			wantSec := []string{"In_Value", "In_Owner", "Secret", "Path_0", "Path_1", "Path_2", "Path_3", "Index", "Extra"}
			if got := leafNames(tr.Witness.Secret); !reflect.DeepEqual(got, wantSec) {
				t.Errorf("secret order\n got %v\nwant %v", got, wantSec)
			}
			if tr.Witness.NbSecret != -1 {
				t.Errorf("Extra is a slice: nb_secret must be dynamic, got %d", tr.Witness.NbSecret)
			}
			if len(tr.Witness.Omit) != 1 || tr.Witness.Omit[0].GoPath != "Debug" {
				t.Errorf("omitted: %+v", tr.Witness.Omit)
			}
			if g := tr.Witness.Public[5]; g.Decl.File != "circuit/transfer.go" || g.Decl.Line != 32 {
				t.Errorf("Out.Value should be attributed to the Out field (line 32), got %+v", g.Decl)
			}
			sig := circuit(t, inv, "SigCircuit")
			if got := leafNames(sig.Witness.Public); !reflect.DeepEqual(got, []string{"PubKey_A_X", "PubKey_A_Y", "Msg"}) {
				t.Errorf("sig public %v", got)
			}
			if got := leafNames(sig.Witness.Secret); !reflect.DeepEqual(got, []string{"Sig_R_X", "Sig_R_Y", "Sig_S", "Amount_Limbs"}) {
				t.Errorf("sig secret %v", got)
			}
			if !circuit(t, inv, "testCircuit").InTest {
				t.Error("testCircuit should be marked in_test_file")
			}
		})
	}
}

func TestPoolHintsAndFootguns(t *testing.T) {
	for _, m := range modes() {
		t.Run(m.name, func(t *testing.T) {
			inv := build(t, "pool", m.syntax)
			status := map[string]string{}
			for _, h := range inv.Hints {
				status[h.HintFunc+"@"+strconv.Itoa(h.Pos.Line)] = h.Status
			}
			want := map[string]string{"divHint@61": "partially_unreached", "splitHint@70": "reached", "splitHint@108": "escapes"}
			if !reflect.DeepEqual(status, want) {
				t.Fatalf("hint status\n got %v\nwant %v", status, want)
			}
			for _, h := range inv.Hints {
				if h.HintFunc == "divHint" {
					if h.Outputs[0].Status != "reached" || h.Outputs[1].Status != "unreached" {
						t.Errorf("divHint outputs: %+v %+v", h.Outputs[0], h.Outputs[1])
					}
					if h.HintDecl == nil || h.HintDecl.File != "circuit/hints.go" {
						t.Errorf("divHint decl not linked: %+v", h.HintDecl)
					}
				}
			}
			for _, hf := range inv.HintFuncs {
				if !hf.Registered {
					t.Errorf("%s should be registered via solver.RegisterHint", hf.Name)
				}
			}
			got := map[string]int{}
			for _, f := range inv.Footguns {
				if !f.InTest {
					got[f.ID]++
				}
			}
			wantFG := map[string]int{
				"FG-HINT-UNREACHED": 1, "FG-HINT-ESCAPES": 1, "FG-DIV-UNCHECKED": 1, "FG-CMP-UNBOUNDED": 1,
				"FG-OMIT-MODULUS-CHECK": 1, "FG-GATED-ASSERT": 1, "FG-GO-BRANCH-ON-WITNESS": 1,
				"FG-DISCARDED-PREDICATE": 1, "FG-EMULATED-WITNESS": 1, "FG-EMULATED-LIMBS": 1,
				"FG-DEV-SETUP": 1, "FG-MIMC": 2, "FG-SIGNATURE": 1, "FG-SKIP-TAG": 1,
			}
			if !reflect.DeepEqual(got, wantFG) {
				t.Errorf("footguns\n got %v\nwant %v", got, wantFG)
			}
			for _, f := range inv.Footguns {
				if f.ID == "FG-CMP-UNBOUNDED" && !strings.Contains(f.Note, "Sub/Neg") {
					t.Errorf("cmp hit should trace the Sub operand: %q", f.Note)
				}
			}
		})
	}
}

func TestPoolContracts(t *testing.T) {
	inv := build(t, "pool", true)
	c := inv.Contracts
	if len(c.Verifiers) != 1 || c.Verifiers[0].Kind != "gnark-groth16" || c.Verifiers[0].NbPublic != 7 {
		t.Fatalf("verifiers: %+v", c.Verifiers)
	}
	if len(c.VerifyCalls) != 1 || c.VerifyCalls[0].Function != "withdraw" || c.VerifyCalls[0].InputArg != "input" || c.VerifyCalls[0].ResultUsed {
		t.Fatalf("verify calls: %+v", c.VerifyCalls)
	}
	var exprs []string
	for _, a := range c.InputAssigns {
		exprs = append(exprs, a.Expr)
	}
	want := []string{"root", "nullifier", "uint256(uint160(recipient))", "fee0", "fee1", "value", "ownerKey"}
	if !reflect.DeepEqual(exprs, want) {
		t.Fatalf("inputs\n got %v\nwant %v", exprs, want)
	}
	kinds := map[string]string{}
	for _, s := range c.StateVars {
		kinds[s.Name] = s.Kind
	}
	if !reflect.DeepEqual(kinds, map[string]string{"verifier": "verifier", "nullifiers": "nullifier", "knownRoots": "root"}) {
		t.Fatalf("state vars: %v", kinds)
	}
	ops := map[string]bool{}
	for _, a := range c.StateAccess {
		ops[a.Name+":"+a.Op+":"+a.Function] = true
	}
	for _, k := range []string{"nullifiers:check:withdraw", "nullifiers:write:withdraw", "knownRoots:check:withdraw", "knownRoots:write:addRoot", "verifier:write:setVerifier"} {
		if !ops[k] {
			t.Errorf("missing state access %s (have %v)", k, ops)
		}
	}
}

// Expected layout from gnark v0.14.0 frontend/schema.Walk on EdgeCircuit
// with len(Many) = 2 and Ptr = nil: public renamed_input, Words_0..5,
// Pts_0_X, Pts_0_Y, Pts_1_X, Pts_1_Y, List_Vals_0, List_Vals_1; secret
// starts with Epoch (the embedded field's tag is ignored).
func TestEdgeLayout(t *testing.T) {
	for _, m := range modes() {
		t.Run(m.name, func(t *testing.T) {
			inv := build(t, "edge", m.syntax)
			c := circuit(t, inv, "EdgeCircuit")
			wantPub := []string{"renamed_input", "Words_0", "Words_1", "Words_2", "Words_3", "Words_4", "Words_5",
				"Pts_0_X", "Pts_0_Y", "Pts_1_X", "Pts_1_Y", "List_Vals_0", "List_Vals_1"}
			if got := leafNames(c.Witness.Public); !reflect.DeepEqual(got, wantPub) {
				t.Errorf("public\n got %v\nwant %v", got, wantPub)
			}
			if c.Witness.NbPublic != 13 {
				t.Errorf("nb_public %d", c.Witness.NbPublic)
			}
			wantSec := []string{"Epoch", "Ptr_X", "Ptr_Y", "Many_{i}", "Big_{i}", "Emu_Limbs", "hidden", "Both"}
			if got := leafNames(c.Witness.Secret); !reflect.DeepEqual(got, wantSec) {
				t.Errorf("secret\n got %v\nwant %v", got, wantSec)
			}
			big := c.Witness.Secret[4]
			if big.Len != 600 || big.StartExpr != "3 + 2*len(Many)" {
				t.Errorf("Big group: len %d start %q", big.Len, big.StartExpr)
			}
			if !strings.Contains(c.Witness.Secret[1].Note, "pointer") {
				t.Errorf("pointer note missing: %q", c.Witness.Secret[1].Note)
			}
			notes := strings.Join(c.Witness.Notes, "\n")
			for _, want := range []string{"embedded field Base has a gnark tag", "unexported field hidden", "interface field Any"} {
				if !strings.Contains(notes, want) {
					t.Errorf("missing note %q in\n%s", want, notes)
				}
			}
			st := map[int]string{}
			for _, h := range inv.Hints {
				st[h.Pos.Line] = h.Status
			}
			want := map[int]string{59: "partially_unreached", 65: "reached", 73: "unreached", 105: "escapes"}
			if !reflect.DeepEqual(st, want) {
				t.Errorf("hints\n got %v\nwant %v", st, want)
			}
			ids := map[string]bool{}
			for _, f := range inv.Footguns {
				ids[f.ID] = true
			}
			for _, id := range []string{"FG-DIV-UNCHECKED", "FG-SELECTOR", "FG-EMULATED-WITNESS", "FG-SKIP-TAG", "FG-HINT-ESCAPES", "FG-HINT-UNREACHED"} {
				if !ids[id] {
					t.Errorf("missing footgun %s", id)
				}
			}
			if ids["FG-GO-BRANCH-ON-WITNESS"] {
				t.Error("`if c.Count > 0` branches on a Go int, not a witness value")
			}
		})
	}
}

func TestRulesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] || !strings.HasPrefix(r.ID, "FG-") || r.Note == "" || r.Title == "" {
			t.Errorf("bad or duplicate rule %+v", r)
		}
		seen[r.ID] = true
	}
	if len(seen) == 0 {
		t.Fatal("no rules")
	}
}

// Two packages each define a type named Circuit; hits must stay with their
// own package.
func TestSameNameCircuits(t *testing.T) {
	dir := t.TempDir()
	src := func(pkg, extra string) string {
		return "package " + pkg + "\n\nimport \"github.com/consensys/gnark/frontend\"\n\n" +
			"type Circuit struct{ X frontend.Variable `gnark:\",public\"` }\n\n" +
			"func (c *Circuit) Define(api frontend.API) error {\n" + extra + "\treturn nil\n}\n"
	}
	for pkg, extra := range map[string]string{"a": "\t_ = api.DivUnchecked(c.X, c.X)\n", "b": ""} {
		if err := os.MkdirAll(filepath.Join(dir, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pkg, "c.go"), []byte(src(pkg, extra)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := load.Load(dir, load.Options{SyntaxOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Build(prog, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Circuits) != 2 {
		t.Fatalf("circuits: %d", len(inv.Circuits))
	}
	for _, c := range inv.Circuits {
		want := 0
		if strings.HasPrefix(c.Define.File, "a/") {
			want = 1
		}
		if len(c.FootgunIDs) != want {
			t.Errorf("%s: footguns %v, want %d", c.Define.File, c.FootgunIDs, want)
		}
	}
}
