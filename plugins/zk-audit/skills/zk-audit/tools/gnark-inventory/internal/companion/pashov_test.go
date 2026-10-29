package companion

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/solidity"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/validate"
)

func inv(t *testing.T) *inventory.Inventory {
	r, err := solidity.ScanRepo(fixture.Dir(t, "sol-inherit"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &inventory.Inventory{Repo: "sol-inherit", Contracts: r}
}

// valid wraps the records in a findings document and validates it.
func valid(t *testing.T, res *Result) {
	t.Helper()
	doc := map[string]any{"schema_version": "1", "repo": "sol-inherit", "run_id": "20261029-120000", "profile": "standard", "records": res.Records}
	b, _ := json.Marshal(doc)
	rep, err := validate.Document("findings", b)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("converted records do not validate: %v", rep.Errors)
	}
}

func byFP(res *Result) map[string]Record {
	m := map[string]Record{}
	for _, r := range res.Records {
		m[r.Fingerprint] = r
	}
	return m
}

func TestConvertRunDirectory(t *testing.T) {
	res, err := ConvertPashov(Options{In: fixture.Dir(t, "pashov-runs", "20261029-120000"), Inventory: inv(t)})
	if err != nil {
		t.Fatal(err)
	}
	valid(t, res)
	if res.Format != "run files" || res.Runs != 2 || len(res.Records) != 3 || len(res.Unresolved) != 1 {
		t.Fatalf("format %s runs %d records %d unresolved %v", res.Format, res.Runs, len(res.Records), res.Unresolved)
	}
	m := byFP(res)
	f, ok := m["Vault|redeem|recipient-not-bound"]
	if !ok {
		t.Fatalf("finding missing: %v", m)
	}
	// the stronger write-up (pass 2, confidence 90) wins; seen in both runs
	if f.Location.File != "src/Vault.sol" || f.Location.Scope != "Vault.redeem" || f.Location.Line < 20 ||
		!strings.Contains(f.Description, "copies a pending redeem") || f.CodeSmells[0] != "solidity-auditor FINDING at confidence 90, seen in 2/2 runs" ||
		f.Verdict != "lead" || f.DetectedBy[0] != "solidity-auditor" {
		t.Errorf("finding: %+v", f)
	}
	l := m["Vault|setFee|unbounded-fee"]
	if strings.Join(l.CodeSmells, ";") != "no upper bound;no event" || l.Unverified != "whether fee is read on any payout path." || strings.Contains(l.Description, "Not verified") {
		t.Errorf("lead: %+v", l)
	}
	if _, ok := m["BaseVault|_checkAndSpend|tag-not-reduced"]; !ok {
		t.Errorf("lead in a base contract not resolved: %v", m)
	}
	var fix string
	for _, it := range res.Items {
		if it.Kind == "FINDING" {
			fix = it.Fix
		}
	}
	if !strings.Contains(fix, "+ pub[2] = uint256(uint160(address(to)));") {
		t.Errorf("fix not kept: %q", fix)
	}
	if u := res.Unresolved[0]; u.Location != "Router.swap" || !strings.Contains(u.Reason, "not in the inventory") {
		t.Errorf("unresolved: %+v", u)
	}
}

func TestConvertSingleRunAndReport(t *testing.T) {
	one, err := ConvertPashov(Options{In: fixture.Dir(t, "pashov-runs", "20261029-120000", "run-1.md"), Inventory: inv(t)})
	if err != nil {
		t.Fatal(err)
	}
	valid(t, one)
	if one.Format != "run file" || len(one.Records) != 2 || byFP(one)["Vault|redeem|recipient-not-bound"].CodeSmells[0] != "solidity-auditor FINDING at confidence 80" {
		t.Errorf("run-1: %+v", one.Records)
	}
	rep, err := ConvertPashov(Options{In: filepath.Join(fixture.Dir(t, "pashov-runs"), "full-report.md"), Inventory: inv(t)})
	if err != nil {
		t.Fatal(err)
	}
	valid(t, rep)
	m := byFP(rep)
	// the full report carries no key: the bug class is the title's slug
	if _, ok := m["Vault|redeem|payout-recipient-is-not-bound-to-the-proof"]; !ok || len(rep.Records) != 2 || len(rep.Unresolved) != 1 {
		t.Errorf("full report: %v unresolved %v", m, rep.Unresolved)
	}
	if _, ok := m["Vault|setFee|relayer-sets-any-fee"]; !ok {
		t.Errorf("full-report lead: %v", m)
	}
}

func TestConvertWithoutInventory(t *testing.T) {
	res, err := ConvertPashov(Options{In: fixture.Dir(t, "pashov-runs", "20261029-120000")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || len(res.Unresolved) != 4 {
		t.Errorf("without an inventory every item is unresolved: %d records, %d unresolved", len(res.Records), len(res.Unresolved))
	}
}

func TestParseRunMissingClose(t *testing.T) {
	src := "<!--RUN pass=1 of=1 stamp=x sha=y agents=12/12-->\n<!--F key=a|b|c conf=80 kind=FINDING agents=1-->\n\n[80] **T**\n\n`A.b` · Confidence: 80\n\n**Description**\nd\n\n<!--F key=a|b|d kind=LEAD agents=1-->\n\n- **L** — `A.b` — Code smells: s — w\n\n<!--/F-->\n"
	bs, pass, warn := parseRun(src)
	if pass != 1 || len(bs) != 2 || len(warn) != 1 || bs[0].desc != "d" || bs[1].smells != "s" {
		t.Errorf("blocks %+v pass %d warn %v", bs, pass, warn)
	}
}
