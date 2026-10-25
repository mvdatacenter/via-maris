package main

import (
	"regexp"
	"strconv"
	"strings"
)

func compareVersions(eco, a, b string) (int, bool) {
	if eco == "PyPI" {
		pa, oka := parsePEP440(a)
		pb, okb := parsePEP440(b)
		if !oka || !okb {
			return 0, false
		}
		return comparePEP440(pa, pb), true
	}
	sa, oka := parseSemver(a)
	sb, okb := parseSemver(b)
	if !oka || !okb {
		return 0, false
	}
	return compareSemver(sa, sb), true
}

type semver struct {
	nums [3]int
	pre  []string
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(s, "v")
	s, _, _ = strings.Cut(s, "+")
	main, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.nums[i] = n
	}
	if hasPre {
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func compareSemver(a, b semver) int {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			return sign(a.nums[i] - b.nums[i])
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		na, ea := strconv.Atoi(a.pre[i])
		nb, eb := strconv.Atoi(b.pre[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				return sign(na - nb)
			}
		case ea == nil:
			return -1
		case eb == nil:
			return 1
		default:
			if c := strings.Compare(a.pre[i], b.pre[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(a.pre) - len(b.pre))
}

var pep440 = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

type pep440Key struct {
	epoch   int
	release []int
	pre     [2]int // phase (-3 dev-only, 0..2 a/b/rc, 3 none), number
	post    int    // -1 none
	dev     int    // max int when none
}

func parsePEP440(s string) (pep440Key, bool) {
	m := pep440.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440Key{}, false
	}
	var k pep440Key
	k.epoch, _ = strconv.Atoi(m[1])
	for _, p := range strings.Split(m[2], ".") {
		n, _ := strconv.Atoi(p)
		k.release = append(k.release, n)
	}
	for len(k.release) > 1 && k.release[len(k.release)-1] == 0 {
		k.release = k.release[:len(k.release)-1]
	}
	k.pre = [2]int{3, 0}
	if m[3] != "" {
		phase := map[string]int{"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}[m[3]]
		n, _ := strconv.Atoi(m[4])
		k.pre = [2]int{phase, n}
	}
	k.post = -1
	if m[5] != "" {
		k.post, _ = strconv.Atoi(m[5])
	} else if m[6] != "" {
		k.post, _ = strconv.Atoi(m[7])
	}
	k.dev = int(^uint(0) >> 1)
	if m[8] != "" {
		k.dev, _ = strconv.Atoi(m[9])
		if m[3] == "" && k.post == -1 {
			k.pre = [2]int{-3, 0}
		}
	}
	return k, true
}

func comparePEP440(a, b pep440Key) int {
	if a.epoch != b.epoch {
		return sign(a.epoch - b.epoch)
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		x, y := 0, 0
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if x != y {
			return sign(x - y)
		}
	}
	for i := 0; i < 2; i++ {
		if a.pre[i] != b.pre[i] {
			return sign(a.pre[i] - b.pre[i])
		}
	}
	if a.post != b.post {
		return sign(a.post - b.post)
	}
	if a.dev != b.dev {
		if a.dev > b.dev {
			return 1
		}
		return -1
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// sameVersion reports whether a and b name one version of eco, so that a
// PyPI pin written "1.0" matches the release "1.0.0".
func sameVersion(eco, a, b string) bool {
	if c, ok := compareVersions(eco, a, b); ok {
		return c == 0
	}
	return a == b
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

func normalizePyPI(name string) string {
	return strings.ToLower(pypiSeparators.ReplaceAllString(name, "-"))
}
