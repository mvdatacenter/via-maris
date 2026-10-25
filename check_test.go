package main

import (
	"testing"
	"time"
)

func checkEnv(t *testing.T, up Upstream, entries ...string) (*testEnv, *Upstream) {
	t.Helper()
	env := newTestEnv(t, up)
	env.osv.set(t, up.Ecosystem, entries...)
	env.loadAdvisories()
	return env, &env.g.cfg.Upstreams[0]
}

func TestCheckAdvisoryPolicy(t *testing.T) {
	ordinary := osvJSON("GHSA-aaaa", "npm", "pkg", nil, []map[string]string{ev("introduced", "0"), ev("fixed", "2.0.0")})
	old := time.Now().Add(-100 * day)

	env, up := checkEnv(t, npmUpstream("http://npm.invalid"), ordinary)
	if vd := env.g.check(up, "pkg", "1.5.0", old); !vd.Served {
		t.Errorf("malicious policy refused an ordinary advisory: %q", vd.Reason)
	}

	all := npmUpstream("http://npm.invalid")
	all.Advisories = "all"
	env, up = checkEnv(t, all, ordinary)
	if vd := env.g.check(up, "pkg", "1.5.0", old); vd.Served || vd.Reason != "carries advisory GHSA-aaaa" {
		t.Errorf("all policy: %+v", vd)
	}
	if vd := env.g.check(up, "pkg", "2.0.0", old); !vd.Served {
		t.Errorf("fixed version refused: %q", vd.Reason)
	}
}

func TestCheckHoldAndExceptions(t *testing.T) {
	up := npmUpstream("http://npm.invalid")
	up.Exceptions = []Exception{
		{Package: "pkg", Version: "1.0.0", Reason: "needed for a fix", Reviewed: "https://example.com/pr/1", Expires: Date{time.Now().Add(day)}},
		{Package: "pkg", Version: "1.1.0", Reason: "lapsed", Reviewed: "https://example.com/pr/2", Expires: Date{time.Now().Add(-day)}},
		{Package: "bad", Version: "1.0.0", Reason: "never admits a listed version", Reviewed: "https://example.com/pr/3", Expires: Date{time.Now().Add(day)}},
	}
	env, cup := checkEnv(t, up, osvJSON("MAL-1", "npm", "bad", []string{"1.0.0"}))
	fresh := time.Now().Add(-time.Hour)

	vd := env.g.check(cup, "pkg", "2.0.0", fresh)
	if vd.Served {
		t.Fatal("a version inside the hold was served")
	}
	wantContains(t, vd.Reason, "published "+fresh.UTC().Format(time.RFC3339), "inside the 168h0m0s release-age hold until "+fresh.Add(7*day).UTC().Format(time.RFC3339))
	if vd := env.g.check(cup, "pkg", "2.0.0", time.Now().Add(-7*day-time.Minute)); !vd.Served {
		t.Errorf("a version past the hold was refused: %q", vd.Reason)
	}
	if vd := env.g.check(cup, "pkg", "1.0.0", fresh); !vd.Served {
		t.Errorf("exception did not admit: %q", vd.Reason)
	} else {
		wantContains(t, vd.Reason, "hold exception reviewed in https://example.com/pr/1", "needed for a fix")
	}
	if vd := env.g.check(cup, "pkg", "1.1.0", fresh); vd.Served {
		t.Error("a lapsed exception admitted")
	}
	if vd := env.g.check(cup, "bad", "1.0.0", fresh); vd.Served || vd.Reason != "listed as malicious by MAL-1" {
		t.Errorf("exception for a listed version: %+v", vd)
	}
}

func TestCheckFixRelease(t *testing.T) {
	entries := []string{
		// GHSA-fix names 1.20.9 as the fix for the 1.x line and 2.4.0 for 2.x.
		osvJSON("GHSA-fix", "npm", "body-parser", nil,
			[]map[string]string{ev("introduced", "2.0.0"), ev("fixed", "2.4.0")},
			[]map[string]string{ev("introduced", "0"), ev("fixed", "1.20.9")}),
		// A fix that is itself listed malicious.
		osvJSON("GHSA-pad", "npm", "left-pad", nil, []map[string]string{ev("introduced", "0"), ev("fixed", "1.3.0")}),
		osvJSON("MAL-pad", "npm", "left-pad", []string{"1.3.0"}),
		// A range ending in last_affected names no fix.
		osvJSON("GHSA-last", "npm", "is-number", nil, []map[string]string{ev("introduced", "0"), ev("last_affected", "6.0.0")}),
	}
	env, up := checkEnv(t, npmUpstream("http://npm.invalid"), entries...)
	fresh := time.Now().Add(-time.Hour)

	vd := env.g.check(up, "body-parser", "1.20.9", fresh)
	if vd.Served || vd.Reason == "" {
		t.Fatalf("before the in-use set loads: %+v", vd)
	}
	wantContains(t, vd.Reason, "it is a fix release, and the in-use set has not loaded")

	env.setInUse(time.Now(), map[string]map[string][]string{"npm": {
		"body-parser": {"1.20.1"}, "left-pad": {"1.2.0"}, "is-number": {"6.0.0"},
	}})
	if vd := env.g.check(up, "body-parser", "1.20.9", fresh); !vd.Served || vd.Reason != "fix release: GHSA-fix names it as the fix for body-parser@1.20.1, which is in use" {
		t.Errorf("fix for a version in use: %+v", vd)
	}
	vd = env.g.check(up, "body-parser", "2.4.0", fresh)
	if vd.Served {
		t.Error("a fix for a line not in use passed the hold")
	}
	wantContains(t, vd.Reason, "it is a fix release for no version in use")
	if vd := env.g.check(up, "left-pad", "1.3.0", fresh); vd.Served || vd.Reason != "listed as malicious by MAL-pad" {
		t.Errorf("malicious fix: %+v", vd)
	}
	if vd := env.g.check(up, "is-number", "7.0.0", fresh); vd.Served {
		t.Errorf("a release after last_affected passed the hold: %+v", vd)
	}

	env.setInUse(time.Now().Add(-2*time.Hour), map[string]map[string][]string{"npm": {"body-parser": {"1.20.1"}}})
	vd = env.g.check(up, "body-parser", "1.20.9", fresh)
	if vd.Served {
		t.Error("a stale in-use set admitted a fix release")
	}
	wantContains(t, vd.Reason, "it is a fix release, and the in-use set is 2h0m0s old, past the 1h0m0s bound")
}

func TestCheckRefusesOnStaleAdvisories(t *testing.T) {
	env, up := checkEnv(t, npmUpstream("http://npm.invalid"))
	env.g.db.mu.Lock()
	env.g.db.eco["npm"].loaded = time.Now().Add(-3 * time.Hour)
	env.g.db.mu.Unlock()
	vd := env.g.check(up, "pkg", "1.0.0", time.Now().Add(-100*day))
	if vd.Served {
		t.Fatal("served on stale advisories")
	}
	wantContains(t, vd.Reason, "advisory data for npm is 3h0m0s old, past the 1h0m0s bound")
	if got := env.g.notReady(); len(got) != 1 || got[0] != "npm advisories" {
		t.Errorf("notReady %v", got)
	}
}
