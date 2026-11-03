package main

import "testing"

// The pairs are ComparableVersion's own: Maven's ComparableVersionTest orders
// these versions so.
func TestCompareMaven(t *testing.T) {
	ascending := []string{
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123",
		"1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1",
		"1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot",
		"1-1", "1-2", "1-123",
	}
	for i := 0; i+1 < len(ascending); i++ {
		a, b := ascending[i], ascending[i+1]
		if c, _ := compareVersions("Maven", a, b); c != -1 {
			t.Errorf("compare(%s, %s) = %d, want -1", a, b, c)
		}
		if c, _ := compareVersions("Maven", b, a); c != 1 {
			t.Errorf("compare(%s, %s) = %d, want 1", b, a, c)
		}
	}
	for _, pair := range [][2]string{
		{"1", "1.0"}, {"1", "1.0.0"}, {"1.0", "1-0"}, {"1", "1-ga"}, {"1", "1.final"},
		{"1", "1-RELEASE"}, {"1a1", "1-alpha-1"}, {"1b2", "1-beta-2"}, {"1m3", "1-milestone-3"},
		{"1X", "1x"}, {"1A", "1a"}, {"1cr", "1rc"}, {"01", "1"},
	} {
		if c, _ := compareVersions("Maven", pair[0], pair[1]); c != 0 {
			t.Errorf("compare(%s, %s) = %d, want 0", pair[0], pair[1], c)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"2.4.21-RC", "2.4.21", -1},
		{"2.4.21", "2.5.0-Beta2", -1},
		{"2.4.21-RC", "2.4.20", 1},
		{"4.13.2", "4.13.10", -1},
		{"1.19.1", "1.19.0", 1},
		{"1.0.0-alpha01", "1.0.0-beta01", -1},
		{"1.0.0-rc01", "1.0.0", -1},
	} {
		if got, _ := compareVersions("Maven", c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInRangeMaven(t *testing.T) {
	r := osvRange{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "2.4.21"}}}
	for v, want := range map[string]bool{"2.4.20": true, "2.4.21-RC": true, "2.4.21": false, "2.5.0": false} {
		if got := inRange("Maven", r, v); got != want {
			t.Errorf("inRange(%s) = %v, want %v", v, got, want)
		}
	}
}
