package main

import (
	"strconv"
	"strings"
)

type mavenItem struct {
	kind int // mavenInt, mavenString or mavenList
	num  string
	str  string
	list []mavenItem
}

const (
	mavenInt = iota
	mavenString
	mavenList
)

// mavenQualifiers are the known qualifiers in ascending order. "" is a
// release, and any other qualifier sorts after them all, lexically.
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

var mavenAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

func mavenQualifierKey(q string) string {
	for i, k := range mavenQualifiers {
		if q == k {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mavenQualifiers)) + "-" + q
}

func mavenStringItem(s string, followedByDigit bool) mavenItem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if a, ok := mavenAliases[s]; ok {
		s = a
	}
	return mavenItem{kind: mavenString, str: s}
}

func mavenIntItem(s string) mavenItem {
	return mavenItem{kind: mavenInt, num: strings.TrimLeft(s, "0")}
}

func (it mavenItem) isNull() bool {
	switch it.kind {
	case mavenInt:
		return it.num == ""
	case mavenString:
		return it.str == ""
	}
	return len(it.list) == 0
}

// normalizeMaven drops the null items that end a list, stopping at the first
// item that is neither null nor a sublist, as ComparableVersion does, so 1.0
// equals 1 and 1-ga equals 1.
func normalizeMaven(l []mavenItem) []mavenItem {
	for i := len(l) - 1; i >= 0; i-- {
		if l[i].isNull() {
			l = append(l[:i], l[i+1:]...)
		} else if l[i].kind != mavenList {
			break
		}
	}
	return l
}

// parseMaven reads a version as ComparableVersion does: "." separates items,
// and "-" or a change between digits and letters starts a sublist.
func parseMaven(v string) []mavenItem {
	v = strings.ToLower(v)
	root := &mavenItem{kind: mavenList}
	// Each list is a pointer into its parent's slice. A parent is never
	// appended to once its sublist is pushed, so the pointers stay valid.
	stack := []*mavenItem{root}
	list := root
	add := func(it mavenItem) { list.list = append(list.list, it) }
	push := func() {
		add(mavenItem{kind: mavenList})
		list = &list.list[len(list.list)-1]
		stack = append(stack, list)
	}
	item := func(s string, digit bool) mavenItem {
		if digit {
			return mavenIntItem(s)
		}
		return mavenStringItem(s, false)
	}
	isDigit, start := false, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '.' || c == '-':
			if i == start {
				add(mavenItem{kind: mavenInt})
			} else {
				add(item(v[start:i], isDigit))
			}
			start = i + 1
			if c == '-' {
				push()
			}
		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				add(mavenStringItem(v[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				add(mavenIntItem(v[start:i]))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		add(item(v[start:], isDigit))
	}
	// Innermost first, so a sublist is normalized before its parent drops it.
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].list = normalizeMaven(stack[i].list)
	}
	return root.list
}

func compareMavenInts(a, b string) int {
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// compareMavenItem compares a with b, where b is nil for the item a shorter
// list lacks past its end.
func compareMavenItem(a mavenItem, b *mavenItem) int {
	switch a.kind {
	case mavenInt:
		switch {
		case b == nil:
			if a.num == "" {
				return 0
			}
			return 1
		case b.kind == mavenInt:
			return compareMavenInts(a.num, b.num)
		}
		return 1
	case mavenString:
		switch {
		case b == nil:
			return strings.Compare(mavenQualifierKey(a.str), mavenQualifierKey(""))
		case b.kind == mavenString:
			return strings.Compare(mavenQualifierKey(a.str), mavenQualifierKey(b.str))
		}
		return -1
	}
	switch {
	case b == nil:
		for _, it := range a.list {
			if c := compareMavenItem(it, nil); c != 0 {
				return c
			}
		}
		return 0
	case b.kind == mavenInt:
		return -1
	case b.kind == mavenString:
		return 1
	}
	return compareMaven(a.list, b.list)
}

func compareMaven(a, b []mavenItem) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		switch {
		case i >= len(a):
			if c := compareMavenItem(b[i], nil); c != 0 {
				return -c
			}
		case i >= len(b):
			if c := compareMavenItem(a[i], nil); c != 0 {
				return c
			}
		default:
			if c := compareMavenItem(a[i], &b[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}
