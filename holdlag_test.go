package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	holdLagMonth = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	holdLagNow   = time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
)

func malJSON(id, eco, pkg string, published time.Time, versions ...string) string {
	b, _ := json.Marshal(map[string]any{
		"id":        id,
		"published": published.Format(time.RFC3339),
		"affected": []map[string]any{{
			"package":  map[string]string{"ecosystem": eco, "name": pkg},
			"versions": versions,
		}},
	})
	return string(b)
}

type fakeRegistries struct {
	mu       sync.Mutex
	npm      map[string]map[string]time.Time
	pypi     map[string]map[string]time.Time
	poms     map[string]time.Time
	goIndex  []goIndexLine
	goCached map[string]bool
}

type goIndexLine struct {
	Path, Version string
	Timestamp     time.Time
}

func newFakeRegistries(t *testing.T) (*fakeRegistries, *httptest.Server) {
	f := &fakeRegistries{npm: map[string]map[string]time.Time{}, pypi: map[string]map[string]time.Time{}, poms: map[string]time.Time{}, goCached: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/npm/"):
			times, ok := f.npm[strings.TrimPrefix(p, "/npm/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			doc := map[string]any{"time": map[string]string{}}
			for v, at := range times {
				doc["time"].(map[string]string)[v] = at.Format(time.RFC3339)
			}
			json.NewEncoder(w).Encode(doc)
		case strings.HasPrefix(p, "/pypi/simple/"):
			files, ok := f.pypi[strings.Trim(strings.TrimPrefix(p, "/pypi/simple/"), "/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			var list []map[string]string
			for name, at := range files {
				list = append(list, map[string]string{"filename": name, "upload-time": at.Format(time.RFC3339)})
			}
			json.NewEncoder(w).Encode(map[string]any{"files": list})
		case strings.HasPrefix(p, "/maven/"):
			at, ok := f.poms[strings.TrimPrefix(p, "/maven/")]
			if !ok || r.Method != http.MethodHead {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Last-Modified", at.Format(http.TimeFormat))
		case strings.HasPrefix(p, "/go/cached-only/"):
			mod, ver, _ := strings.Cut(strings.TrimPrefix(p, "/go/cached-only/"), "/@v/")
			if !f.goCached[mod+"@"+strings.TrimSuffix(ver, ".info")] {
				http.Error(w, "not cached", http.StatusGone)
				return
			}
			fmt.Fprint(w, "{}")
		case p == "/goindex/index":
			since, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
			for _, l := range f.goIndex {
				if !l.Timestamp.Before(since) {
					json.NewEncoder(w).Encode(l)
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

type holdLagEnv struct {
	t     *testing.T
	osv   *osvExport
	store *fakeStore
	am    *fakeAlertmanager
	reg   *fakeRegistries
	path  string
}

func newHoldLagEnv(t *testing.T) *holdLagEnv {
	t.Helper()
	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	env := &holdLagEnv{t: t}
	var osvSrv, storeSrv, amSrv, regSrv *httptest.Server
	env.osv, osvSrv = newOSVExport(t)
	env.store, storeSrv = newFakeStore(t)
	env.am, amSrv = newFakeAlertmanager(t)
	env.reg, regSrv = newFakeRegistries(t)
	store := map[string]string{"endpoint": storeSrv.URL, "region": "test", "bucket": "bucket", "accessKeyIdEnv": "TEST_KEY_ID", "secretAccessKeyEnv": "TEST_SECRET"}
	gw := map[string]any{
		"listen":     ":8480",
		"advisories": map[string]string{"source": osvSrv.URL, "refresh": "15m", "maxAge": "2h"},
		"inUse":      map[string]any{"store": map[string]string{"endpoint": storeSrv.URL, "region": "test", "bucket": "in-use", "accessKeyIdEnv": "IN_USE_KEY_UNSET", "secretAccessKeyEnv": "IN_USE_SECRET_UNSET"}, "object": "in-use.json", "refresh": "5m", "maxAge": "1h"},
		"records":    map[string]any{"store": store, "prefix": "records/", "interval": "10s", "maxUnshipped": "5m"},
		"upstreams": []map[string]any{
			{"name": "npm", "ecosystem": "npm", "url": regSrv.URL + "/npm", "hold": "720h", "advisories": "malicious"},
			{"name": "pypi", "ecosystem": "PyPI", "url": regSrv.URL + "/pypi", "files": regSrv.URL + "/files", "hold": "720h", "advisories": "malicious"},
			{"name": "central", "ecosystem": "Maven", "url": regSrv.URL + "/maven", "hold": "720h", "advisories": "malicious"},
			{"name": "go", "ecosystem": "Go", "url": regSrv.URL + "/go", "index": regSrv.URL + "/goindex", "sumdb": regSrv.URL + "/sumdb", "indexPoll": "1m", "indexMaxAge": "5m", "hold": "168h", "advisories": "malicious"},
			{"name": "apt", "ecosystem": "apt", "url": regSrv.URL + "/apt", "hold": "168h"},
		},
	}
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "gateway.json"), gw)
	env.path = filepath.Join(dir, "hold-lag.json")
	writeJSON(t, env.path, map[string]string{"gateway": filepath.Join(dir, "gateway.json"), "goWindow": "1440h", "alertmanager": amSrv.URL, "alertFor": "768h"})
	for _, eco := range []string{"npm", "PyPI", "Maven", "Go"} {
		env.osv.set(t, eco)
	}
	return env
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (env *holdLagEnv) run(month string) (*HoldLagReport, error) {
	env.t.Helper()
	cfg, gw, err := loadHoldLagConfig(env.path)
	if err != nil {
		env.t.Fatal(err)
	}
	return newHoldLagRun(cfg, gw, http.DefaultClient, holdLagNow).run(context.Background(), month)
}

func (r *HoldLagReport) ecosystem(t *testing.T, eco string) HoldLagEcosystem {
	t.Helper()
	for _, e := range r.Ecosystems {
		if e.Ecosystem == eco {
			return e
		}
	}
	t.Fatalf("report has no %s: %+v", eco, r.Ecosystems)
	return HoldLagEcosystem{}
}

func (env *holdLagEnv) npmMonth(n, long int, lagLong, lagShort time.Duration) []string {
	var entries []string
	for i := 0; i < n; i++ {
		listed := holdLagMonth.Add(time.Duration(i) * time.Hour)
		lag := lagShort
		if i < long {
			lag = lagLong
		}
		pkg := fmt.Sprintf("evil-%03d", i)
		env.reg.npm[pkg] = map[string]time.Time{"1.0.0": listed.Add(-lag)}
		entries = append(entries, malJSON(fmt.Sprintf("MAL-2026-%04d", i), "npm", pkg, listed, "1.0.0"))
	}
	return entries
}

func TestHoldLagPostsOutOfBandWhenAMonthLeavesMoreThanAQuarterUnlisted(t *testing.T) {
	env := newHoldLagEnv(t)
	// 40 of 120 (33%) listed 40 days after publication, past the 30-day hold.
	entries := env.npmMonth(120, 40, 40*day, 2*day)
	listed := holdLagMonth.Add(200 * time.Hour)
	// Removed from the registry, dated by its decision record alone.
	entries = append(entries, malJSON("MAL-2026-9001", "npm", "gone-recorded", listed, "2.0.0"))
	env.store.put(recordsKey(listed.Add(-time.Hour)), recordsObject(record{Time: listed.Format(time.RFC3339), Ecosystem: "npm", Kind: "artifact", Package: "gone-recorded", Version: "2.0.0", Published: listed.Add(-3 * day).Format(time.RFC3339)}))
	// Removed and never asked for: undated.
	entries = append(entries, malJSON("MAL-2026-9002", "npm", "gone-unrecorded", listed, "3.0.0"))
	// Published after its entry was listed: counted apart.
	env.reg.npm["late-added"] = map[string]time.Time{"4.0.0": listed.Add(time.Hour)}
	entries = append(entries, malJSON("MAL-2026-9003", "npm", "late-added", listed, "4.0.0"))
	// Named by range alone, and listed outside the month: neither is counted.
	entries = append(entries, malJSON("MAL-2026-9004", "npm", "range-only", listed))
	entries = append(entries, malJSON("MAL-2026-9005", "npm", "evil-000", holdLagMonth.Add(-time.Hour), "9.9.9"))
	env.osv.set(t, "npm", entries...)

	report, err := env.run("2026-10")
	if err != nil {
		t.Fatal(err)
	}
	npm := report.ecosystem(t, "npm")
	if npm.Entries != 124 || npm.EntriesNamingNoVersions != 1 || npm.Versions != 123 {
		t.Errorf("npm entries %d (%d naming no versions), versions %d; want 124 (1), 123", npm.Entries, npm.EntriesNamingNoVersions, npm.Versions)
	}
	if npm.Dated != 121 || npm.Undated != 1 || npm.PublishedAfterListing != 1 || npm.DatedFrom["registry"] != 120 || npm.DatedFrom["record"] != 1 {
		t.Errorf("npm dated %d %v, undated %d, after listing %d; want 121 (120 registry, 1 record), 1, 1", npm.Dated, npm.DatedFrom, npm.Undated, npm.PublishedAfterListing)
	}
	if npm.UnlistedAtHold != 40 || npm.Thin || !npm.OutOfBand {
		t.Errorf("npm unlisted %d, thin %v, out of band %v; want 40, false, true", npm.UnlistedAtHold, npm.Thin, npm.OutOfBand)
	}
	// 40 of 121 is 33% below 40 days, and none is unlisted at 40.
	if npm.ShortestHold != (40 * day).String() {
		t.Errorf("npm shortest hold %s, want %s", npm.ShortestHold, 40*day)
	}
	if len(env.am.alerts) != 1 {
		t.Fatalf("posted %d alerts, want 1: %+v", len(env.am.alerts), env.am.alerts)
	}
	labels := env.am.alerts[0]["labels"].(map[string]any)
	if labels["alertname"] != "ViaMarisHoldLagOutOfBand" || labels["ecosystem"] != "npm" || labels["month"] != "2026-10" || labels["severity"] != "ticket" {
		t.Errorf("alert labels %v", labels)
	}
	ann := env.am.alerts[0]["annotations"].(map[string]any)
	wantContains(t, ann["summary"].(string), "40 of the 121", "33.1%", "720h0m0s hold")
	wantContains(t, ann["description"].(string), "960h0m0s", filepath.Join(filepath.Dir(env.path), "gateway.json"))
	starts, _ := time.Parse(time.RFC3339, env.am.alerts[0]["startsAt"].(string))
	ends, _ := time.Parse(time.RFC3339, env.am.alerts[0]["endsAt"].(string))
	if ends.Sub(starts) != 768*time.Hour {
		t.Errorf("alert lasts %s, want alertFor's 768h", ends.Sub(starts))
	}
}

func TestHoldLagPostsNothingForAMonthInsideTheBand(t *testing.T) {
	env := newHoldLagEnv(t)
	// 24 of 120 (20%) listed past the hold.
	env.osv.set(t, "npm", env.npmMonth(120, 24, 40*day, 2*day)...)
	report, err := env.run("2026-10")
	if err != nil {
		t.Fatal(err)
	}
	if npm := report.ecosystem(t, "npm"); npm.OutOfBand || npm.UnlistedAtHold != 24 || npm.ShortestHold != (2*day).String() {
		t.Errorf("npm %+v; want 24 unlisted, in band, shortest hold 2 days", npm)
	}
	if len(env.am.alerts) != 0 {
		t.Errorf("posted %v for a month inside the band", env.am.alerts)
	}
}

func TestAThinMonthMovesNothingAndPyPIAndMavenFollowNPM(t *testing.T) {
	env := newHoldLagEnv(t)
	// Every one of npm's 10 is past the hold, but 10 is a thin month.
	env.osv.set(t, "npm", env.npmMonth(10, 10, 40*day, 0)...)
	listed := holdLagMonth.Add(48 * time.Hour)
	env.reg.pypi["evil-py"] = map[string]time.Time{
		"evil_py-1.0-py3-none-any.whl": listed.Add(-5 * day),
		"evil-py-1.0.tar.gz":           listed.Add(-6 * day),
	}
	env.osv.set(t, "PyPI", malJSON("MAL-2026-2001", "PyPI", "Evil.Py", listed, "1.0"))
	env.reg.poms["org/evil/core/1.2/core-1.2.pom"] = listed.Add(-35 * day)
	env.osv.set(t, "Maven", malJSON("MAL-2026-3001", "Maven", "org.evil:core", listed, "1.2"))
	report, err := env.run("2026-10")
	if err != nil {
		t.Fatal(err)
	}
	npm, pypi, maven := report.ecosystem(t, "npm"), report.ecosystem(t, "PyPI"), report.ecosystem(t, "Maven")
	if !npm.Thin || npm.OutOfBand || npm.UnlistedAtHold != 10 {
		t.Errorf("npm %+v; want thin, not out of band, 10 unlisted", npm)
	}
	if pypi.Dated != 1 || pypi.UnlistedAtHold != 0 || !pypi.Thin {
		t.Errorf("PyPI %+v; want 1 dated from its earliest file, 6 days, not unlisted, thin", pypi)
	}
	if maven.Dated != 1 || maven.UnlistedAtHold != 1 || maven.DatedFrom["registry"] != 1 {
		t.Errorf("Maven %+v; want 1 dated by its .pom, unlisted at the hold", maven)
	}
	wantContains(t, pypi.Note, "follows npm's")
	wantContains(t, maven.Note, "follows npm's")
	if strings.Contains(npm.Note, "follows") {
		t.Errorf("npm's note %q says it follows another hold", npm.Note)
	}
	if len(env.am.alerts) != 0 {
		t.Errorf("posted %v for thin months", env.am.alerts)
	}
}

func TestGoVersionsAreDatedFromTheIndexOrBoundedByItsWindow(t *testing.T) {
	env := newHoldLagEnv(t)
	listed := holdLagMonth.Add(10 * day)
	env.reg.goIndex = []goIndexLine{
		{"example.com/other", "v1.0.0", holdLagMonth.Add(-2 * day)},
		{"example.com/evil", "v1.0.0", listed.Add(-9 * day)},
	}
	// v0.9.0 was first served before the 60-day window, v0.1.0 never.
	env.reg.goCached["example.com/evil@v0.9.0"] = true
	env.osv.set(t, "Go", malJSON("MAL-2026-4001", "Go", "example.com/evil", listed, "1.0.0", "0.9.0", "0.1.0"))
	report, err := env.run("2026-10")
	if err != nil {
		t.Fatal(err)
	}
	g := report.ecosystem(t, "Go")
	if g.Dated != 2 || g.Undated != 1 || g.DatedFrom["index"] != 1 || g.DatedFrom["before the index window"] != 1 {
		t.Errorf("Go %+v; want 2 dated (1 from the index, 1 before its window), 1 undated", g)
	}
	// Both are past the 168h hold: 9 days, and at least 70.
	if g.UnlistedAtHold != 2 {
		t.Errorf("Go unlisted %d, want 2", g.UnlistedAtHold)
	}
	// Half stay unlisted until the 70-day bound, which no hold reaches.
	if g.ShortestHold != "" {
		t.Errorf("Go shortest hold %q, want none inside the window", g.ShortestHold)
	}
	wantContains(t, g.Note, "thin", "index window reaches")
}

func TestShortestHoldStopsShortOfALowerBound(t *testing.T) {
	lags := []lag{{3 * day, false}, {5 * day, true}}
	// Half the lags are unlisted below 3 days, and from 5 days on the bound
	// cannot be judged, so no hold is named.
	lags = append(lags, lag{5 * day, true}, lag{6 * day, true})
	if days, ok := shortestHoldDays(lags); ok {
		t.Errorf("named %d days past a lower bound", days)
	}
	if days, ok := shortestHoldDays([]lag{{3 * day, false}, {30 * day, true}, {time.Hour, false}, {time.Hour, false}, {time.Hour, false}}); !ok || days != 3 {
		t.Errorf("shortest hold %d %v, want 3 days", days, ok)
	}
}

func TestALongerGoHoldNotesTheGatewayStartUp(t *testing.T) {
	report := &HoldLagReport{Ecosystems: []HoldLagEcosystem{
		{Ecosystem: "Go", Hold: "168h0m0s", ShortestHold: "240h0m0s"},
		{Ecosystem: "Go", Hold: "168h0m0s", ShortestHold: "96h0m0s"},
	}}
	follow(report)
	wantContains(t, report.Ecosystems[0].Note, "/healthz reports ready")
	if n := report.Ecosystems[1].Note; n != "" {
		t.Errorf("a shorter Go hold noted %q", n)
	}
}

func TestHoldLagReadsTheMonthBeforeTheRun(t *testing.T) {
	start, end, err := monthBounds("", time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC))
	if err != nil || start.Format("2006-01") != "2025-12" || end.Format("2006-01") != "2026-01" {
		t.Errorf("month before 2026-01-01: %s to %s, %v", start, end, err)
	}
	env := newHoldLagEnv(t)
	if _, err := env.run("2026-11"); err == nil || !strings.Contains(err.Error(), "has not ended") {
		t.Errorf("a month not yet ended: %v", err)
	}
}

func TestAnUnreachableRecordsStoreFailsTheRun(t *testing.T) {
	env := newHoldLagEnv(t)
	env.osv.set(t, "npm", env.npmMonth(1, 0, 0, day)...)
	env.store.setFail(true)
	if _, err := env.run("2026-10"); err == nil || !strings.Contains(err.Error(), "records") {
		t.Errorf("run with the store down: %v", err)
	}
}

func TestAnAlertmanagerRefusalFailsTheRun(t *testing.T) {
	env := newHoldLagEnv(t)
	env.osv.set(t, "npm", env.npmMonth(120, 60, 40*day, day)...)
	env.am.down = true
	if _, err := env.run("2026-10"); err == nil {
		t.Error("the run succeeded though its out-of-band alert was not posted")
	}
}

func TestHoldLagRefusesEcosystemUpstreamsWithDifferentHolds(t *testing.T) {
	env := newHoldLagEnv(t)
	var gw map[string]any
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(env.path), "gateway.json"))
	json.Unmarshal(b, &gw)
	ups := gw["upstreams"].([]any)
	ups = append(ups, map[string]any{"name": "google", "ecosystem": "Maven", "url": "https://dl.google.com/dl/android/maven2", "hold": "168h", "advisories": "malicious"})
	gw["upstreams"] = ups
	writeJSON(t, filepath.Join(filepath.Dir(env.path), "gateway.json"), gw)
	if _, _, err := loadHoldLagConfig(env.path); err == nil || !strings.Contains(err.Error(), "no one Maven hold") {
		t.Errorf("loaded Maven upstreams holding 720h and 168h: %v", err)
	}
}

func TestHoldLagRefusesAGoWindowNoLongerThanTheGoHold(t *testing.T) {
	env := newHoldLagEnv(t)
	var hl map[string]any
	b, _ := os.ReadFile(env.path)
	json.Unmarshal(b, &hl)
	hl["goWindow"] = "168h"
	writeJSON(t, env.path, hl)
	if _, _, err := loadHoldLagConfig(env.path); err == nil || !strings.Contains(err.Error(), "must exceed the Go hold") {
		t.Errorf("loaded a goWindow equal to the 168h Go hold: %v", err)
	}
}

func TestExampleHoldLagConfigLoads(t *testing.T) {
	setExampleKeys(t)
	cfg, gw, err := loadHoldLagConfig("hold-lag.example.json")
	if err != nil {
		t.Fatal(err)
	}
	run := newHoldLagRun(cfg, gw, nil, holdLagNow)
	got := run.ecosystems()
	sort.Strings(got)
	if strings.Join(got, " ") != "Go Maven PyPI npm" || cfg.GoWindow.Duration != 60*day {
		t.Errorf("ecosystems %v, goWindow %s", got, cfg.GoWindow.Duration)
	}
}
