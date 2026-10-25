package main

import "testing"

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		eco, a, b string
		want      int
	}{
		{"npm", "1.2.3", "1.2.10", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"npm", "1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"npm", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"npm", "1.0.0+build", "1.0.0", 0},
		{"Go", "v0.0.0-20230101000000-abcdef123456", "v0.1.0", -1},
		{"PyPI", "1.0", "1.0.0", 0},
		{"PyPI", "1.0a1", "1.0", -1},
		{"PyPI", "1.0.dev1", "1.0a1", -1},
		{"PyPI", "1.0.post1", "1.0", 1},
		{"PyPI", "1!0.1", "2.0", 1},
		{"PyPI", "2026.10.19", "2025.1.31", 1},
	} {
		got, ok := compareVersions(c.eco, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("compareVersions(%s, %s, %s) = %d %v, want %d", c.eco, c.a, c.b, got, ok, c.want)
		}
	}
	if _, ok := compareVersions("npm", "1.2", "1.2.0"); ok {
		t.Error("compared a version that is not semver")
	}
}

func TestInRange(t *testing.T) {
	r := osvRange{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "1.0.0"}, {Fixed: "1.2.0"}, {Introduced: "2.0.0"}, {LastAffected: "2.1.0"}}}
	for v, want := range map[string]bool{
		"0.9.0": false, "1.0.0": true, "1.1.9": true, "1.2.0": false,
		"2.0.0": true, "2.1.0": true, "2.1.1": false,
		"not-a-version": true, // what cannot be compared is affected, so it is refused
	} {
		if got := inRange("npm", r, v); got != want {
			t.Errorf("inRange(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestNormalizePyPI(t *testing.T) {
	if got := normalizePyPI("Zope.Interface__x"); got != "zope-interface-x" {
		t.Errorf("normalizePyPI = %s", got)
	}
}
