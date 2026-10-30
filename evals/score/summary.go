package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type stat struct{ n, mean, sd, min, max float64 }

func stats(vs []float64) (stat, bool) {
	if len(vs) == 0 {
		return stat{}, false
	}
	s := stat{n: float64(len(vs)), min: math.Inf(1), max: math.Inf(-1)}
	for _, v := range vs {
		s.mean += v
		s.min = math.Min(s.min, v)
		s.max = math.Max(s.max, v)
	}
	s.mean /= s.n
	for _, v := range vs {
		s.sd += (v - s.mean) * (v - s.mean)
	}
	if s.n > 1 {
		s.sd = math.Sqrt(s.sd / (s.n - 1))
	}
	return s, true
}

func pct(s stat, ok bool) string {
	if !ok {
		return "–"
	}
	if s.n == 1 {
		return fmt.Sprintf("%.0f %%", 100*s.mean)
	}
	return fmt.Sprintf("%.0f %% ± %.0f (%.0f–%.0f)", 100*s.mean, 100*s.sd, 100*s.min, 100*s.max)
}

func num(s stat, ok bool, f string) string {
	if !ok {
		return "–"
	}
	if s.n == 1 {
		return fmt.Sprintf(f, s.mean)
	}
	return fmt.Sprintf(f+" ± "+f, s.mean, s.sd)
}

// summarize renders one table row per case and a per-item hit table.
func summarize(rs []*Result) string {
	byCase := map[string][]*Result{}
	var cases []string
	for _, r := range rs {
		if _, ok := byCase[r.Case]; !ok {
			cases = append(cases, r.Case)
		}
		byCase[r.Case] = append(byCase[r.Case], r)
	}
	sort.Strings(cases)
	var b strings.Builder
	b.WriteString("| Case | Runs | Recall | Critical recall | False positives | Precision | Severity agreement | PoC rate | Cost (USD) | Time (min) |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range cases {
		group := byCase[c]
		col := func(f func(*Result) *float64) (stat, bool) {
			var vs []float64
			for _, r := range group {
				if v := f(r); v != nil {
					vs = append(vs, *v)
				}
			}
			return stats(vs)
		}
		recall := func(r *Result) *float64 { return r.Recall }
		fps := func(r *Result) *float64 { v := float64(len(r.FalsePositives)); return &v }
		mins := func(r *Result) *float64 {
			if r.DurationS == nil {
				return nil
			}
			v := *r.DurationS / 60
			return &v
		}
		rec, rok := col(recall)
		crit, cok := col(func(r *Result) *float64 { return r.CriticalRecall })
		fp, fok := col(fps)
		pr, pok := col(func(r *Result) *float64 { return r.Precision })
		sv, sok := col(func(r *Result) *float64 { return r.SeverityAgree })
		pc, pcok := col(func(r *Result) *float64 { return r.PoCRate })
		co, cook := col(func(r *Result) *float64 { return r.CostUSD })
		du, duok := col(mins)
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s |\n", c, len(group),
			pct(rec, rok), pct(crit, cok), num(fp, fok, "%.1f"), pct(pr, pok), pct(sv, sok), pct(pc, pcok),
			num(co, cook, "%.2f"), num(du, duok, "%.1f"))
	}
	for _, c := range cases {
		group := byCase[c]
		fmt.Fprintf(&b, "\n**%s**: per-item outcomes over %d run(s)\n\n| Item | Title | Outcomes |\n|---|---|---|\n", c, len(group))
		order := []string{}
		outcomes := map[string][]string{}
		titles := map[string]string{}
		for _, r := range group {
			for _, it := range append(append([]ItemResult{}, r.Items...), r.Decoys...) {
				if _, ok := outcomes[it.ID]; !ok {
					order = append(order, it.ID)
					titles[it.ID] = it.Title
				}
				o := it.Outcome
				if it.Best != "" && o != "handled" {
					o += " (" + it.Best + ")"
				}
				outcomes[it.ID] = append(outcomes[it.ID], o)
			}
		}
		for _, id := range order {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", id, titles[id], strings.Join(outcomes[id], " · "))
		}
		for _, r := range group {
			if r.Error != "" {
				fmt.Fprintf(&b, "\n- %s: run error: %s\n", label(r), r.Error)
			}
			for _, fp := range r.FalsePositives {
				fmt.Fprintf(&b, "- %s: false positive: %s\n", label(r), fp)
			}
		}
	}
	return b.String()
}

func label(r *Result) string {
	if r.Label != "" {
		return r.Label
	}
	return r.Case
}
