package advisory

import (
	"fmt"
	"testing"
)

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
	// unknown version: every gnark advisory possibly affected
	unk := tab.Affecting("(devel)")
	n := 0
	for _, a := range tab.Advisories {
		if a.Package == Gnark {
			n++
		}
	}
	if len(unk) != n || unk[0].Status != "possibly_affected" {
		t.Errorf("unknown version should be possibly_affected by every gnark advisory (%d), got %d", n, len(unk))
	}
	// a pseudo-version just before v0.16.4 is still affected by GHSA-7fx8
	if !ids(tab.Affecting("v0.16.4-0.20261001000000-abcdefabcdef"))["GHSA-7fx8-hmgc-82jp"] {
		t.Errorf("pre-v0.16.4 pseudo-version should be affected by GHSA-7fx8")
	}
}

func TestGnarkCryptoRanges(t *testing.T) {
	tab, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	has := func(module, v, id string) bool {
		for _, m := range tab.AffectingModule(module, v) {
			if m.ID == id {
				return true
			}
		}
		return false
	}
	// GHSA-fj2x has two ranges: [v0.9.1, v0.18.1) and [v0.19.0, v0.19.2)
	for v, want := range map[string]bool{"v0.9.0": false, "v0.9.1": true, "v0.18.0": true, "v0.18.1": false, "v0.18.2": false, "v0.19.0": true, "v0.19.1": true, "v0.19.2": false, "v0.21.0": false} {
		if got := has(GnarkCrypto, v, "GHSA-fj2x-735w-74vq"); got != want {
			t.Errorf("gnark-crypto %s affected by GHSA-fj2x = %v, want %v", v, got, want)
		}
	}
	if !has(GnarkCrypto, "v0.11.2", "GHSA-fr8m-434r-g3xp") || has(GnarkCrypto, "v0.12.0", "GHSA-fr8m-434r-g3xp") {
		t.Error("GHSA-fr8m: want affected below v0.12.0 only")
	}
	// gnark-crypto advisories never match a gnark version and vice versa
	if has(Gnark, "v0.10.0", "GHSA-fj2x-735w-74vq") || has(GnarkCrypto, "v0.8.0", "GHSA-498w-5j49-vqjg") {
		t.Error("advisories leaked across modules")
	}
	for _, a := range tab.Advisories {
		if !a.Verified || a.Evidence == "" {
			t.Errorf("%s: every row records how it was verified (verified_by, evidence)", a.ID)
		}
	}
	if got := tab.Advisories[0].Affected(); got != "< v0.16.4" {
		t.Errorf("Affected() = %q", got)
	}
}

func TestParseRejectsBadRows(t *testing.T) {
	base := `{"schema_version":"2","as_of":"2026-10-29","packages":["github.com/consensys/gnark"],"sources":[],"advisories":[%s]}`
	row := `{"id":"GHSA-x","aliases":[],"package":"%s","severity":"low","class":"soundness","component":"c","summary":"s","introduced":"0","fixed":"v0.1.0","action":"a","regenerate_keys":false,"url":"https://x","verified":%s%s}`
	for name, r := range map[string]string{
		"unknown package":         fmt.Sprintf(row, "example.com/x", "false", ""),
		"verified without source": fmt.Sprintf(row, Gnark, "true", ""),
		"source without verified": fmt.Sprintf(row, Gnark, "false", `,"verified_by":"osv"`),
		"duplicate id":            fmt.Sprintf(row, Gnark, "false", "") + "," + fmt.Sprintf(row, Gnark, "false", ""),
	} {
		if _, err := Parse([]byte(fmt.Sprintf(base, r))); err == nil {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
	if _, err := Parse([]byte(fmt.Sprintf(base, fmt.Sprintf(row, Gnark, "false", "")))); err != nil {
		t.Errorf("good row rejected: %v", err)
	}
}
