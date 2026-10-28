package advisory

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.9.0", "v0.9.0", 0},
		{"v0.9.0", "v0.9.1", -1},
		{"v0.10.0", "v0.9.9", 1},
		{"v0.16.4-0.20261009142911-8911ee45d22b", "v0.16.4", -1},
		{"v0.16.5-0.20261009142911-8911ee45d22b", "v0.16.4", 1},
		{"v1.0.0-rc.1", "v1.0.0-rc.2", -1},
		{"v1.0.0-alpha", "v1.0.0-1", 1},
		{"v0.14.0+incompatible", "v0.14.0", 0},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := Compare(a, b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestTableLoadsAndMatches(t *testing.T) {
	tab, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.Advisories) < 11 {
		t.Fatalf("expected at least 11 advisories, got %d", len(tab.Advisories))
	}
	ids := func(ms []Match) map[string]bool {
		m := map[string]bool{}
		for _, x := range ms {
			m[x.ID] = true
		}
		return m
	}
	if got := tab.Affecting("v0.16.4"); len(got) != 0 {
		t.Errorf("v0.16.4 should match nothing, got %v", ids(got))
	}
	got := ids(tab.Affecting("v0.12.0"))
	for _, want := range []string{"GHSA-9fvj-xqr2-xwg8", "GHSA-95v9-hv42-pwrj", "GHSA-3mvx-pp85-pm65", "GHSA-7fx8-hmgc-82jp"} {
		if !got[want] {
			t.Errorf("v0.12.0 should be affected by %s", want)
		}
	}
	if got["GHSA-q3hw-3gm4-w5cr"] || got["GHSA-498w-5j49-vqjg"] {
		t.Errorf("v0.12.0 should not match fixed-in-0.11 / 0.9 advisories: %v", got)
	}
	// GHSA-9fvj was introduced in v0.12.0.
	if ids(tab.Affecting("v0.11.0"))["GHSA-9fvj-xqr2-xwg8"] {
		t.Errorf("v0.11.0 predates GHSA-9fvj")
	}
	// unknown version: everything possibly affected
	unk := tab.Affecting("(devel)")
	if len(unk) != len(tab.Advisories) || unk[0].Status != "possibly_affected" {
		t.Errorf("unknown version should be possibly_affected by all")
	}
	// a pseudo-version just before v0.16.4 is still affected by GHSA-7fx8
	if !ids(tab.Affecting("v0.16.4-0.20261001000000-abcdefabcdef"))["GHSA-7fx8-hmgc-82jp"] {
		t.Errorf("pre-v0.16.4 pseudo-version should be affected by GHSA-7fx8")
	}
}
