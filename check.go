package main

import (
	"fmt"
	"time"
)

type verdict struct {
	Served bool
	Reason string
}

func refusal(pkg, version string, v verdict) string {
	return fmt.Sprintf("via-maris refused %s@%s: %s", pkg, version, v.Reason)
}

func (g *gateway) advisoryRefusal(up *Upstream, pkg, version string) (verdict, bool) {
	if why := g.advisoriesUnusable(up.Ecosystem); why != "" {
		return verdict{false, why}, false
	}
	for _, a := range g.db.lookup(up.Ecosystem, pkg) {
		if !a.affects(up.Ecosystem, version) {
			continue
		}
		if a.Malicious {
			return verdict{false, fmt.Sprintf("listed as malicious by %s", a.ID)}, false
		}
		if up.Advisories == "all" {
			return verdict{false, fmt.Sprintf("carries advisory %s", a.ID)}, false
		}
	}
	return verdict{true, ""}, true
}

func (g *gateway) advisoriesUnusable(eco string) string {
	age, loaded := g.db.age(eco)
	if !loaded {
		return fmt.Sprintf("advisory data for %s has not loaded", eco)
	}
	if age > g.cfg.Advisories.MaxAge.Duration {
		return fmt.Sprintf("advisory data for %s is %s old, past the %s bound", eco, age.Round(time.Second), g.cfg.Advisories.MaxAge.Duration)
	}
	return ""
}

func (g *gateway) check(up *Upstream, pkg, version string, published time.Time) verdict {
	if vd, ok := g.advisoryRefusal(up, pkg, version); !ok {
		return vd
	}
	now := time.Now()
	for _, e := range up.Exceptions {
		if packageKey(up.Ecosystem, e.Package) == packageKey(up.Ecosystem, pkg) && sameVersion(up.Ecosystem, e.Version, version) && now.Before(e.Expires.Time) {
			return verdict{true, fmt.Sprintf("hold exception reviewed in %s until %s: %s", e.Reviewed, e.Expires.Format(time.DateOnly), e.Reason)}
		}
	}
	if published.IsZero() {
		return verdict{false, "the upstream gives no publication time"}
	}
	if now.Sub(published) >= up.Hold.Duration {
		return verdict{true, ""}
	}
	held := fmt.Sprintf("published %s, inside the %s release-age hold until %s",
		published.UTC().Format(time.RFC3339), up.Hold.Duration, published.Add(up.Hold.Duration).UTC().Format(time.RFC3339))
	adv, inUse, named := g.fixFor(up.Ecosystem, pkg, version)
	if !named {
		return verdict{false, held}
	}
	age, _, loaded := g.inUse.age()
	switch {
	case !loaded:
		return verdict{false, held + "; it is a fix release, and the in-use set has not loaded"}
	case age > g.cfg.InUse.MaxAge.Duration:
		return verdict{false, fmt.Sprintf("%s; it is a fix release, and the in-use set is %s old, past the %s bound",
			held, age.Round(time.Second), g.cfg.InUse.MaxAge.Duration)}
	case adv == "":
		return verdict{false, held + "; it is a fix release for no version in use"}
	}
	return verdict{true, fmt.Sprintf("fix release: %s names it as the fix for %s@%s, which is in use", adv, pkg, inUse)}
}

func (g *gateway) fixFor(eco, pkg, version string) (adv, inUse string, named bool) {
	for _, a := range g.db.lookup(eco, pkg) {
		if a.Malicious {
			continue
		}
		for _, r := range a.fixedAt(eco, version) {
			named = true
			for _, u := range g.inUse.versions(eco, pkg) {
				if comparable(eco, r, u) && inRange(eco, r, u) {
					return a.ID, u, true
				}
			}
		}
	}
	return "", "", named
}
