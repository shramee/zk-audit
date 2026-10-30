package estimate

import (
	"math"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/load"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

// The model with the measured agent counts must give back the measured cost
// and time of every calibration run, within the stated spread.
func TestModelReproducesMeasuredRuns(t *testing.T) {
	c := Load()
	if len(c.Runs) == 0 || c.Source == "" {
		t.Fatal("calibration has no runs or no source")
	}
	for _, r := range c.Runs {
		if _, ok := profile.Load().Profile(r.Profile); !ok {
			t.Errorf("calibration run names unknown profile %q", r.Profile)
			continue
		}
		n := Counts{HunterTokensPerPass: r.Hunters * c.HunterTokens(r.Profile, c.ReferenceSourceLines), Hunters: r.Hunters, Passes: 1,
			PoC: r.PoC, Refuters: r.Refuters, Critics: r.Critics, Waves: r.Waves}
		tok := float64(c.Tokens(n))
		if d := math.Abs(tok/1e6-r.SubagentMTok) / r.SubagentMTok; d > 0.15 {
			t.Errorf("%s: model tokens %.2fM, measured %.2fM (off by %.0f%%)", r.Profile, tok/1e6, r.SubagentMTok, d*100)
		}
		usd := tok / 1e6 * c.USDPerMTok.Mid
		if usd < r.USD*0.8 || usd > r.USD*1.2 {
			t.Errorf("%s: model cost %.2f USD, measured %.2f", r.Profile, usd, r.USD)
		}
		lo, hi := tok*c.TokenSpread.Low/1e6*c.USDPerMTok.Low, tok*c.TokenSpread.High/1e6*c.USDPerMTok.High
		if r.USD < lo || r.USD > hi {
			t.Errorf("%s: measured %.2f USD outside the model's range %.1f-%.1f", r.Profile, r.USD, lo, hi)
		}
		m := c.MinutesFor(n)
		if r.Minutes < m*c.Minutes.SpreadLow || r.Minutes > m*c.Minutes.SpreadHigh {
			t.Errorf("%s: measured %.1f min outside the model's range %.1f-%.1f", r.Profile, r.Minutes, m*c.Minutes.SpreadLow, m*c.Minutes.SpreadHigh)
		}
	}
}

func TestHunterTokensScaleWithShard(t *testing.T) {
	c := Load()
	ref := c.HunterTokens("quick", c.ReferenceSourceLines)
	if ref != c.Roles.Hunter["quick"] {
		t.Errorf("reference shard: %d, want %d", ref, c.Roles.Hunter["quick"])
	}
	if big := c.HunterTokens("quick", 2000); big <= ref {
		t.Errorf("a 2000-line shard should cost more than the reference: %d <= %d", big, ref)
	}
	if small := c.HunterTokens("quick", 0); small < int(0.6*float64(ref)) {
		t.Errorf("floor not applied: %d", small)
	}
}

func poolInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	root := fixture.Dir(t, "pool")
	prog, err := load.Load(root, load.Options{SyntaxOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Build(prog, inventory.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestPoolEstimate(t *testing.T) {
	inv := poolInventory(t)
	rep, err := Profiles(inv, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Estimate{}
	for _, e := range rep.Estimates {
		got[e.Profile] = e
	}
	if _, ok := got["library"]; ok {
		t.Error("library profile estimated for a repository with production circuits")
	}
	q, s, d := got["quick"], got["standard"], got["deep"]
	if q.Hunters == 0 || s.Hunters <= q.Hunters || d.Hunters < s.Hunters {
		t.Errorf("hunters: quick %d, standard %d, deep %d", q.Hunters, s.Hunters, d.Hunters)
	}
	// the measured quick run (15 hunters then, 16 now with T1) lies in the range
	if q.USD.Low > 9.16 || q.USD.High < 9.16 {
		t.Errorf("quick range %.1f-%.1f USD does not hold the measured 9.16", q.USD.Low, q.USD.High)
	}
	if s.USD.Low > 26.09 || s.USD.High < 26.09 {
		t.Errorf("standard range %.1f-%.1f USD does not hold the measured 26.09", s.USD.Low, s.USD.High)
	}
	if d.Passes.High != 3 || d.Passes.Low != 2 || d.USD.High <= s.USD.High {
		t.Errorf("deep: passes %v, cost %v (standard %v)", d.Passes, d.USD, s.USD)
	}
	if q.PoCBuilders.High >= s.PoCBuilders.High {
		t.Errorf("quick proves only critical/high findings: %v vs %v", q.PoCBuilders, s.PoCBuilders)
	}
	for _, e := range rep.Estimates {
		if e.Measured == nil {
			t.Errorf("%s: no measured run attached", e.Profile)
		}
	}
	np, err := Profiles(inv, []string{"standard"}, Options{NoPoC: true, Passes: 2})
	if err != nil {
		t.Fatal(err)
	}
	if e := np.Estimates[0]; e.PoCBuilders.High != 0 || e.Refuters.High == 0 || e.Passes.High != 2 {
		t.Errorf("--no-poc --loop 2: %+v", e)
	}
	if _, err := Profiles(inv, []string{"nope"}, Options{}); err == nil {
		t.Error("unknown profile accepted")
	}
	if md := rep.Markdown(); md == "" || !strings.Contains(md, "Calibration: ") || !strings.Contains(md, "| quick |") {
		t.Errorf("markdown:\n%s", md)
	}
}
