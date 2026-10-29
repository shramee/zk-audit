package modcache

import "testing"

func TestCompareGo(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"go1.24.7", "1.24.0", 1},
		{"1.24", "1.24.0", 0},
		{"go1.25.7", "1.26.8", -1},
		{"go1.21rc1", "1.21.0", -1},
		{"go1.26.10", "go1.26.8", 1},
		{"go1.24.7 X:nocoverageredesign", "1.24.7", 0},
	} {
		if got := CompareGo(c.a, c.b); got != c.want {
			t.Errorf("CompareGo(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := Escape("github.com/Consensys/gnark"); got != "github.com/!consensys/gnark" {
		t.Errorf("Escape = %q", got)
	}
}
