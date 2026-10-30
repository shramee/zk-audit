// Package estimate predicts the agents, tokens, cost and wall-clock time of
// an audit from the inventory before any agent is spawned, calibrated
// against measured runs (calibration.json). It is deterministic: the same
// inventory and profile give the same numbers. It never claims precision it
// does not have: every figure is a range, and the calibration source is part
// of the output.
package estimate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/bundle"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/inventory"
	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/profile"
)

//go:embed calibration.json
var rawCalibration []byte

// Calibration is calibration.json.
type Calibration struct {
	SchemaVersion        string  `json:"schema_version"`
	Source               string  `json:"source"`
	Fixture              string  `json:"fixture"`
	ReferenceSourceLines int     `json:"reference_source_lines"`
	TokensPerSourceLine  float64 `json:"tokens_per_source_line"`
	USDPerMTok           struct {
		Low  float64 `json:"low"`
		Mid  float64 `json:"mid"`
		High float64 `json:"high"`
		Note string  `json:"note"`
	} `json:"usd_per_mtok"`
	TokenSpread struct {
		Low  float64 `json:"low"`
		High float64 `json:"high"`
	} `json:"token_spread"`
	Roles struct {
		Hunter  map[string]int `json:"hunter"`
		PoC     int            `json:"poc"`
		Refuter int            `json:"refuter"`
		Critic  int            `json:"critic"`
		Wave    int            `json:"wave"`
	} `json:"roles"`
	Confirmed struct {
		Low            int    `json:"low"`
		High           int    `json:"high"`
		ReferenceLines int    `json:"reference_lines"`
		MinHigh        int    `json:"min_high"`
		MaxHigh        int    `json:"max_high"`
		Note           string `json:"note"`
	} `json:"confirmed_per_reference"`
	Minutes struct {
		Fixed        float64 `json:"fixed"`
		HuntBatch    float64 `json:"hunt_batch"`
		PoCBatch     float64 `json:"poc_batch"`
		RefuterBatch float64 `json:"refuter_batch"`
		Critic       float64 `json:"critic"`
		Wave         float64 `json:"wave"`
		SpreadLow    float64 `json:"spread_low"`
		SpreadHigh   float64 `json:"spread_high"`
	} `json:"minutes"`
	PoolSize   int   `json:"pool_size"`
	Runs       []Run `json:"runs"`
	Unmeasured []struct {
		Case    string `json:"case"`
		Profile string `json:"profile"`
		Flags   string `json:"flags"`
		Note    string `json:"note"`
	} `json:"unmeasured"`
}

// Run is one measured run.
type Run struct {
	Profile      string  `json:"profile"`
	Flags        string  `json:"flags"`
	USD          float64 `json:"usd"`
	Minutes      float64 `json:"minutes"`
	Agents       int     `json:"agents"`
	Hunters      int     `json:"hunters"`
	PoC          int     `json:"poc"`
	Refuters     int     `json:"refuters"`
	Critics      int     `json:"critics"`
	Waves        int     `json:"waves"`
	SubagentMTok float64 `json:"subagent_mtok"`
	Note         string  `json:"note,omitempty"`
}

var cal *Calibration

// Load returns the embedded calibration. It panics on a malformed file: the
// file ships inside the binary and a test parses it.
func Load() *Calibration {
	if cal == nil {
		var c Calibration
		if err := json.Unmarshal(rawCalibration, &c); err != nil {
			panic("estimate: calibration.json: " + err.Error())
		}
		cal = &c
	}
	return cal
}

// Range is a low-high pair.
type Range struct {
	Low  int `json:"low"`
	High int `json:"high"`
}

// RangeF is a low-high pair of decimals.
type RangeF struct {
	Low  float64 `json:"low"`
	High float64 `json:"high"`
}

// Options change what the estimate assumes.
type Options struct {
	Passes int  // 0: the profile's passes
	NoPoC  bool // --no-poc: no PoC builders (refuters still run)
}

// Agent is one planned hunter.
type Agent struct {
	ID          string `json:"id"`
	Shard       string `json:"shard"`
	SourceLines int    `json:"source_lines"`
	Tokens      int    `json:"tokens"`
}

// Estimate is the prediction for one profile.
type Estimate struct {
	Profile      string   `json:"profile"`
	Passes       RangeF   `json:"passes"`
	Hunters      int      `json:"hunters_per_pass"`
	HunterTokens int      `json:"hunter_tokens_per_pass"`
	Confirmed    Range    `json:"expected_confirmed"`
	PoCBuilders  Range    `json:"poc_builders"`
	Refuters     Range    `json:"refuters"`
	Critics      Range    `json:"critics"`
	Waves        Range    `json:"targeted_waves"`
	Agents       Range    `json:"agents"`
	Tokens       Range    `json:"tokens"`
	USD          RangeF   `json:"usd"`
	Minutes      RangeF   `json:"minutes"`
	SourceLines  int      `json:"in_scope_source_lines"`
	Skipped      []string `json:"skipped_lenses"`
	PerAgent     []Agent  `json:"per_agent"`
	Measured     *Run     `json:"measured_on_calibration_fixture,omitempty"`
	Notes        []string `json:"notes"`
}

// Report is the estimate for every profile asked for.
type Report struct {
	Calibration string     `json:"calibration"`
	Rate        string     `json:"usd_per_million_tokens"`
	Estimates   []Estimate `json:"estimates"`
	Assumptions []string   `json:"assumptions"`
}

// HunterTokens predicts one hunter's tokens from its shard size: the
// calibrated per-hunter figure of the profile at the reference shard size,
// plus or minus tokens per source line, never below 60 % of the reference.
func (c *Calibration) HunterTokens(prof string, sourceLines int) int {
	ref, ok := c.Roles.Hunter[prof]
	if !ok {
		ref = c.Roles.Hunter["standard"]
	}
	t := float64(ref) + c.TokensPerSourceLine*float64(sourceLines-c.ReferenceSourceLines)
	if min := 0.6 * float64(ref); t < min {
		t = min
	}
	return int(math.Round(t))
}

// Counts are the agents of one run shape.
type Counts struct {
	HunterTokensPerPass int
	Hunters             int
	Passes              int
	PoC                 int
	Refuters            int
	Critics             int
	Waves               int
}

// Tokens is the calibrated token total for c.
func (c *Calibration) Tokens(n Counts) int {
	return n.HunterTokensPerPass*n.Passes + n.PoC*c.Roles.PoC + n.Refuters*c.Roles.Refuter + n.Critics*c.Roles.Critic + n.Waves*c.Roles.Wave
}

// MinutesFor is the calibrated wall-clock time for c, with the bounded pool of
// agents running in batches.
func (c *Calibration) MinutesFor(n Counts) float64 {
	m := c.Minutes
	batches := func(n int) float64 {
		if n <= 0 {
			return 0
		}
		return math.Ceil(float64(n) / float64(c.PoolSize))
	}
	return m.Fixed + float64(n.Passes)*batches(n.Hunters)*m.HuntBatch + batches(n.PoC)*m.PoCBatch +
		batches(n.Refuters)*m.RefuterBatch + float64(n.Critics)*m.Critic + float64(n.Waves)*m.Wave
}

// Profiles estimates every profile in ids (all profiles when empty) for inv.
func Profiles(inv *inventory.Inventory, ids []string, opt Options) (*Report, error) {
	c := Load()
	set := profile.Load()
	if len(ids) == 0 {
		for _, id := range set.ProfileIDs() {
			if id != "library" || LibraryTarget(inv) {
				ids = append(ids, id)
			}
		}
	}
	shards, err := bundle.Shards(inv)
	if err != nil {
		return nil, err
	}
	rep := &Report{
		Calibration: c.Source,
		Rate:        fmt.Sprintf("%.1f-%.1f USD per million subagent tokens (%s)", c.USDPerMTok.Low, c.USDPerMTok.High, c.USDPerMTok.Note),
		Assumptions: []string{
			fmt.Sprintf("a hunter costs the measured tokens of its profile at a %d-line shard, %g tokens more or less per source line", c.ReferenceSourceLines, c.TokensPerSourceLine),
			"one PoC builder per confirmed finding the profile's PoC policy covers and one refuter per confirmed finding; " + c.Confirmed.Note,
			"a profile with several passes runs between two passes (the stop rule needs a second pass to see nothing new) and all of them",
			"cost is the measured blended rate; the Agent tool does not report cost per agent, so a run's spend is tracked in tokens (`budget`)",
		},
	}
	for _, id := range ids {
		p, ok := set.Profile(id)
		if !ok {
			return nil, fmt.Errorf("estimate: unknown profile %q (want %v)", id, set.ProfileIDs())
		}
		plan, err := bundle.Plan(inv, shards, id)
		if err != nil {
			return nil, err
		}
		e := Estimate{Profile: id, Skipped: []string{}, PerAgent: []Agent{}, Notes: []string{}}
		inScope := map[string]int{}
		for _, a := range plan {
			if a.Skip != "" {
				if a.Lens.In(id) {
					e.Skipped = append(e.Skipped, a.ID+": "+a.Skip)
				}
				continue
			}
			n := bundle.SourceLines(inv, a.Shard)
			t := c.HunterTokens(id, n)
			e.PerAgent = append(e.PerAgent, Agent{ID: a.ID, Shard: a.Shard.Name, SourceLines: n, Tokens: t})
			e.Hunters++
			e.HunterTokens += t
			for _, f := range a.Shard.Files {
				if _, ok := inScope[f]; !ok {
					inScope[f] = bundle.SourceLines(inv, bundle.Shard{Files: []string{f}})
				}
			}
		}
		for _, n := range inScope {
			e.SourceLines += n
		}
		passes := p.Passes
		if opt.Passes > 0 {
			passes = opt.Passes
		}
		lowPasses := passes
		if lowPasses > 2 {
			lowPasses = 2
		}
		e.Passes = RangeF{float64(lowPasses), float64(passes)}
		ratio := float64(e.SourceLines) / float64(c.Confirmed.ReferenceLines)
		hi := int(math.Ceil(float64(c.Confirmed.High) * ratio))
		if hi < c.Confirmed.MinHigh {
			hi = c.Confirmed.MinHigh
		}
		if hi > c.Confirmed.MaxHigh {
			hi = c.Confirmed.MaxHigh
		}
		e.Confirmed = Range{c.Confirmed.Low, hi}
		pocHi := hi
		switch {
		case opt.NoPoC:
			pocHi = 0
			e.Notes = append(e.Notes, "--no-poc: no PoC builders; refuters still run")
		case len(p.PoC.Severities) < 5:
			pocHi = (hi + 1) / 2
			e.Notes = append(e.Notes, "PoC policy: "+p.PoC.Text)
		}
		e.PoCBuilders = Range{0, pocHi}
		e.Refuters = Range{0, hi}
		perPassCritics := 0
		final := 0
		for _, cr := range p.Critics {
			if cr == "final-clean" {
				final++
			} else {
				perPassCritics++
			}
		}
		e.Critics = Range{perPassCritics*lowPasses + final, perPassCritics*passes + final}
		e.Waves = Range{p.TargetedWaves * lowPasses, p.TargetedWaves * passes}
		low := Counts{HunterTokensPerPass: e.HunterTokens, Hunters: e.Hunters, Passes: lowPasses, PoC: 0, Refuters: 0, Critics: e.Critics.Low, Waves: e.Waves.Low}
		high := Counts{HunterTokensPerPass: e.HunterTokens, Hunters: e.Hunters, Passes: passes, PoC: pocHi, Refuters: hi, Critics: e.Critics.High, Waves: e.Waves.High}
		e.Agents = Range{e.Hunters*lowPasses + low.Critics + low.Waves, e.Hunters*passes + high.PoC + high.Refuters + high.Critics + high.Waves}
		e.Tokens = Range{int(float64(c.Tokens(low)) * c.TokenSpread.Low), int(float64(c.Tokens(high)) * c.TokenSpread.High)}
		e.USD = RangeF{round1(float64(e.Tokens.Low) / 1e6 * c.USDPerMTok.Low), round1(float64(e.Tokens.High) / 1e6 * c.USDPerMTok.High)}
		e.Minutes = RangeF{round1(c.MinutesFor(low) * c.Minutes.SpreadLow), round1(c.MinutesFor(high) * c.Minutes.SpreadHigh)}
		for i := range c.Runs {
			if c.Runs[i].Profile == id {
				r := c.Runs[i]
				e.Measured = &r
			}
		}
		if passes > 1 {
			e.Notes = append(e.Notes, fmt.Sprintf("%d passes with memory; the calibration run of this profile ran one pass, so later passes are extrapolated", passes))
		}
		if e.Hunters == 0 {
			e.Notes = append(e.Notes, "no bundle would be written: every shard of the profile is empty")
		}
		sort.Strings(e.Skipped)
		rep.Estimates = append(rep.Estimates, e)
	}
	return rep, nil
}

// LibraryTarget reports whether the inventory has exported gadgets and no
// production circuit, the case the library profile is for.
func LibraryTarget(inv *inventory.Inventory) bool {
	if len(inv.Gadgets) == 0 {
		return false
	}
	for _, c := range inv.Circuits {
		if !c.InTest {
			return false
		}
	}
	return true
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// Markdown renders the report as a table and notes.
func (r *Report) Markdown() string {
	var s string
	s += "| Profile | Hunters | Passes | PoC builders | Refuters | Critics + waves | Agents | Tokens | Cost (USD) | Time (min) |\n"
	s += "|---|---|---|---|---|---|---|---|---|---|\n"
	for _, e := range r.Estimates {
		passes := fmt.Sprintf("%g", e.Passes.High)
		if e.Passes.Low != e.Passes.High {
			passes = fmt.Sprintf("%g-%g", e.Passes.Low, e.Passes.High)
		}
		s += fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %s | %s | %.0f-%.0f | %.0f-%.0f |\n", e.Profile, e.Hunters, passes,
			rng(e.PoCBuilders), rng(e.Refuters), rng(Range{e.Critics.Low + e.Waves.Low, e.Critics.High + e.Waves.High}), rng(e.Agents),
			fmt.Sprintf("%.1f-%.1fM", float64(e.Tokens.Low)/1e6, float64(e.Tokens.High)/1e6), math.Floor(e.USD.Low), math.Ceil(e.USD.High),
			math.Floor(e.Minutes.Low), math.Ceil(e.Minutes.High))
	}
	s += "\nCalibration: " + r.Calibration + ".\n"
	for _, e := range r.Estimates {
		if m := e.Measured; m != nil {
			s += fmt.Sprintf("Measured %s on the calibration fixture: %.2f USD, %.1f min, %d agents.\n", e.Profile, m.USD, m.Minutes, m.Agents)
		}
	}
	s += "Rate: " + r.Rate + ".\n\nAssumptions:\n\n"
	for _, a := range r.Assumptions {
		s += "- " + a + ".\n"
	}
	for _, e := range r.Estimates {
		for _, n := range e.Notes {
			s += "- " + e.Profile + ": " + n + ".\n"
		}
	}
	return s
}

func rng(r Range) string {
	if r.Low == r.High {
		return fmt.Sprint(r.High)
	}
	return fmt.Sprintf("%d-%d", r.Low, r.High)
}
