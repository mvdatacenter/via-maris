package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func malJSON(id, eco, published string, affected map[string][]string) string {
	var as []map[string]any
	for pkg, versions := range affected {
		as = append(as, map[string]any{"package": map[string]string{"ecosystem": eco, "name": pkg}, "versions": versions})
	}
	b, _ := json.Marshal(map[string]any{"id": id, "published": published, "affected": as})
	return string(b)
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

type fakeRegistries struct {
	mu       sync.Mutex
	npm      map[string]map[string]string
	pypi     map[string]map[string]string
	index    []map[string]string
	cached   map[string]bool
	fail     bool
	asked    []string
	sinceGot []string
}

func newFakeRegistries(t *testing.T) (*fakeRegistries, *httptest.Server) {
	f := &fakeRegistries{npm: map[string]map[string]string{}, pypi: map[string]map[string]string{}, cached: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.asked = append(f.asked, r.URL.Path)
		if f.fail {
			http.Error(w, "registry down", http.StatusInternalServerError)
			return
		}
		p := r.URL.Path
		switch {
		case p == "/index":
			since, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
			f.sinceGot = append(f.sinceGot, r.URL.Query().Get("since"))
			for _, e := range f.index {
				if !at(e["Timestamp"]).Before(since) {
					b, _ := json.Marshal(e)
					w.Write(append(b, '\n'))
				}
			}
		case strings.HasPrefix(p, "/cached-only/"):
			mod, ver, _ := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(p, "/cached-only/"), ".info"), "/@v/")
			if !f.cached[mod+"@"+ver] {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"Version":%q}`, ver)
		case strings.HasPrefix(p, "/pypi/"):
			project := strings.TrimSuffix(strings.TrimPrefix(p, "/pypi/"), "/json")
			rel, ok := f.pypi[project]
			if !ok {
				http.NotFound(w, r)
				return
			}
			releases := map[string][]map[string]string{}
			for v, up := range rel {
				releases[v] = []map[string]string{{"upload_time_iso_8601": up}, {"upload_time_iso_8601": "2030-01-01T00:00:00Z"}}
			}
			json.NewEncoder(w).Encode(map[string]any{"releases": releases})
		default:
			times, ok := f.npm[strings.TrimPrefix(p, "/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"time": times})
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

type holdLagEnv struct {
	t     *testing.T
	osv   *osvExport
	store *fakeStore
	reg   *fakeRegistries
	am    *fakeAlertmanager
	amURL string
	gw    map[string]any
	run   *holdLagRun
}

func newHoldLagEnv(t *testing.T) *holdLagEnv {
	t.Helper()
	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	env := &holdLagEnv{t: t}
	var osvSrv, storeSrv, regSrv, amSrv *httptest.Server
	env.osv, osvSrv = newOSVExport(t)
	env.store, storeSrv = newFakeStore(t)
	env.reg, regSrv = newFakeRegistries(t)
	env.am, amSrv = newFakeAlertmanager(t)
	env.amURL = amSrv.URL
	store := map[string]string{"endpoint": storeSrv.URL, "region": "test", "bucket": "bucket", "accessKeyIdEnv": "TEST_KEY_ID", "secretAccessKeyEnv": "TEST_SECRET"}
	// The gateway's own configuration, with the sections this job holds no
	// key for: the report must not need them.
	env.gw = map[string]any{
		"listen":     ":8480",
		"advisories": map[string]string{"source": osvSrv.URL, "refresh": "15m", "maxAge": "2h"},
		"inUse":      map[string]any{"store": map[string]string{"endpoint": storeSrv.URL, "region": "test", "bucket": "in-use", "accessKeyIdEnv": "UNSET_KEY", "secretAccessKeyEnv": "UNSET_SECRET"}, "object": "in-use.json", "refresh": "5m", "maxAge": "1h"},
		"records":    map[string]any{"store": store, "prefix": "records/", "interval": "10s", "maxUnshipped": "5m"},
		"upstreams": []map[string]any{
			{"name": "go", "ecosystem": "Go", "url": regSrv.URL, "index": regSrv.URL, "sumdb": regSrv.URL, "indexPoll": "1m", "indexMaxAge": "5m", "hold": "168h", "advisories": "malicious"},
			{"name": "pypi", "ecosystem": "PyPI", "url": regSrv.URL, "files": regSrv.URL, "hold": "720h", "advisories": "malicious"},
			{"name": "npm", "ecosystem": "npm", "url": regSrv.URL, "hold": "720h", "advisories": "malicious"},
			{"name": "apt", "ecosystem": "apt", "url": regSrv.URL, "hold": "168h"},
		},
		"byName": map[string]any{"listen": ":8443", "upstream": "pypi", "cert": "/nonexistent/tls.crt", "key": "/nonexistent/tls.key", "ca": "/nonexistent/ca.crt"},
	}
	env.osv.set(t, "npm")
	env.osv.set(t, "PyPI")
	env.osv.set(t, "Go")
	return env
}

func (env *holdLagEnv) files() (holdLag, gateway string) {
	env.t.Helper()
	dir := env.t.TempDir()
	gateway = filepath.Join(dir, "via-maris.json")
	b, _ := json.Marshal(env.gw)
	os.WriteFile(gateway, b, 0o644)
	holdLag = filepath.Join(dir, "hold-lag.json")
	b, _ = json.Marshal(map[string]any{
		"gatewayConfig": gateway, "alertmanager": env.amURL, "alertFor": "744h",
		"target": 0.2, "low": 0.15, "high": 0.25, "minDated": 5, "maxHoldDays": 365, "goWindow": "720h",
	})
	os.WriteFile(holdLag, b, 0o644)
	return holdLag, gateway
}

func (env *holdLagEnv) newRun() *holdLagRun {
	env.t.Helper()
	path, _ := env.files()
	cfg, err := loadHoldLagConfig(path)
	if err != nil {
		env.t.Fatal(err)
	}
	gw, err := readHoldLagGateway(cfg.GatewayConfig, http.DefaultClient)
	if err != nil {
		env.t.Fatal(err)
	}
	return &holdLagRun{cfg: cfg, gw: gw, client: http.DefaultClient, retryWait: time.Millisecond}
}

// october is a month of npm listings whose share at the 30-day hold is two
// of six dated versions, past the 25% bound.
func (env *holdLagEnv) october() {
	env.osv.set(env.t, "npm",
		malJSON("MAL-1", "npm", "2026-10-03T00:00:00Z", map[string][]string{"a": {"1.0.0", "1.0.1"}}),
		malJSON("MAL-2", "npm", "2026-10-10T00:00:00Z", map[string][]string{"b": {"2.0.0"}}),
		// Removed from the registry, dated by the gateway's record.
		malJSON("MAL-3", "npm", "2026-10-06T00:00:00Z", map[string][]string{"c": {"1.0.0"}}),
		// Removed, and no record dates it.
		malJSON("MAL-4", "npm", "2026-10-06T00:00:00Z", map[string][]string{"d": {"1.0.0"}}),
		// Published after its entry listed it.
		malJSON("MAL-5", "npm", "2026-10-15T00:00:00Z", map[string][]string{"e": {"1.0.0"}}),
		malJSON("MAL-6", "npm", "2026-10-02T00:00:00Z", map[string][]string{"@scope/f": {"1.0.0"}}),
		malJSON("MAL-7", "npm", "2026-10-12T00:00:00Z", map[string][]string{"g": {"1.0.0"}}),
		// A later entry naming a version already listed: counted once.
		malJSON("MAL-8", "npm", "2026-10-20T00:00:00Z", map[string][]string{"g": {"1.0.0"}}),
		malJSON("MAL-9", "npm", "2026-10-21T00:00:00Z", map[string][]string{"h": nil}),
		// Outside the month, and not malicious.
		malJSON("MAL-10", "npm", "2026-09-30T23:59:59Z", map[string][]string{"x": {"1.0.0"}}),
		malJSON("MAL-11", "npm", "2026-11-01T00:00:00Z", map[string][]string{"x": {"1.0.1"}}),
		malJSON("GHSA-xxxx", "npm", "2026-10-05T00:00:00Z", map[string][]string{"y": {"1.0.0"}}),
	)
	env.reg.npm["a"] = map[string]string{"1.0.0": "2026-10-01T00:00:00.000Z", "1.0.1": "2026-10-02T00:00:00.000Z"}
	env.reg.npm["b"] = map[string]string{"2.0.0": "2026-08-01T00:00:00.000Z"}
	env.reg.npm["e"] = map[string]string{"1.0.0": "2026-10-20T00:00:00.000Z"}
	env.reg.npm["@scope/f"] = map[string]string{"1.0.0": "2026-10-01T00:00:00.000Z"}
	env.reg.npm["g"] = map[string]string{"1.0.0": "2026-07-01T00:00:00.000Z"}
	recorded := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	env.store.put(recordsKey(recorded), recordsObject(
		record{Time: recorded.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "c", Version: "1.0.0", Served: true, Published: "2026-10-05T00:00:00Z"},
		record{Time: recorded.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "c", Version: "1.0.0", Served: true, Published: "2026-10-05T06:00:00Z"},
		record{Time: recorded.Format(time.RFC3339Nano), Ecosystem: "PyPI", Kind: "artifact", Package: "Gone_Project", Version: "0.1", Served: true, Published: "2026-10-01T00:00:00Z"},
	))
}

func TestHoldLagMeasuresTheShareStillUnlistedWhenTheHoldEnded(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	r := env.newRun()
	rep, err := r.run(context.Background(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Month != "2026-10" || len(rep.Ecosystems) != 3 || rep.Ecosystems[0].Ecosystem != "npm" || rep.Ecosystems[1].Ecosystem != "PyPI" || rep.Ecosystems[2].Ecosystem != "Go" {
		t.Fatalf("report %+v, want npm, PyPI and Go for 2026-10", rep)
	}
	npm := rep.Ecosystems[0]
	want := ecosystemReport{Ecosystem: "npm", Hold: "720h0m0s", Entries: 9, NoVersions: 1, Dated: 6, Undated: 1, AfterListing: 1,
		Unlisted: 2, Share: 2.0 / 6, ProposedDays: 70, SearchedDays: 365, OutOfBand: true}
	if npm != want {
		t.Errorf("npm\n got %+v\nwant %+v", npm, want)
	}
	// c's record carries two times; the earlier dates it, 1 day before its
	// listing, which is inside every hold.
	if s := npm.String(); !strings.Contains(s, "2 (33.3%) unlisted when the hold ended") || !strings.Contains(s, "70 days") || !strings.Contains(s, "OUT OF BAND") {
		t.Errorf("npm line %q", s)
	}
}

func TestHoldLagFlagsAThinMonthAndRaisesNothingForIt(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	env.osv.set(t, "PyPI",
		malJSON("MAL-20", "PyPI", "2026-10-08T00:00:00Z", map[string][]string{"evil-pkg": {"1.0"}}),
		malJSON("MAL-21", "PyPI", "2026-10-09T00:00:00Z", map[string][]string{"gone-project": {"0.1"}}),
	)
	// Released as 1.0.0; PEP 440 reads it as the 1.0 the entry names.
	env.reg.pypi["evil-pkg"] = map[string]string{"1.0.0": "2026-06-01T00:00:00Z"}
	r := env.newRun()
	rep, err := r.run(context.Background(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	py := rep.Ecosystems[1]
	if py.Dated != 2 || py.Unlisted != 1 || !py.Thin || py.OutOfBand || py.Note != "thin, so PyPI's hold follows npm's" {
		t.Errorf("PyPI %+v, want two dated, one past the hold, thin and following npm", py)
	}
	if goRep := rep.Ecosystems[2]; goRep.Dated != 0 || !goRep.Thin || goRep.OutOfBand || goRep.Note != "thin, so this month moves nothing" {
		t.Errorf("Go %+v, want an empty thin month", goRep)
	}
	alerts := r.alerts(rep)
	if len(alerts) != 1 || alerts[0].Labels["ecosystem"] != "npm" {
		t.Errorf("alerts %+v, want npm's alone", alerts)
	}
	for _, p := range env.reg.asked {
		if strings.HasPrefix(p, "/index") {
			t.Errorf("read the module index for a month with no Go version to date: %s", p)
		}
	}
}

func TestHoldLagDatesAGoVersionFromTheIndexAndNeverFetchesIt(t *testing.T) {
	env := newHoldLagEnv(t)
	env.osv.set(t, "Go",
		malJSON("MAL-30", "Go", "2026-10-06T00:00:00Z", map[string][]string{"example.com/Evil": {"v1.0.0"}}),
		malJSON("MAL-31", "Go", "2026-10-07T00:00:00Z", map[string][]string{"example.com/Old": {"v0.1.0"}}),
		malJSON("MAL-32", "Go", "2026-10-07T00:00:00Z", map[string][]string{"example.com/gone": {"v1.0.0"}}),
	)
	env.reg.index = []map[string]string{
		{"Path": "example.com/other", "Version": "v1.0.0", "Timestamp": "2026-09-02T00:00:00Z"},
		{"Path": "example.com/Evil", "Version": "v1.0.0", "Timestamp": "2026-10-05T00:00:00Z"},
		{"Path": "example.com/Evil", "Version": "v1.0.0", "Timestamp": "2026-10-05T01:00:00Z"},
	}
	// The proxy is asked by the escaped path; asked otherwise, it has nothing.
	env.reg.cached["example.com/!old@v0.1.0"] = true
	r := env.newRun()
	rep, err := r.run(context.Background(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g := rep.Ecosystems[2]
	// Old was first served before the window, which began 2026-09-01, so
	// its lag is known to reach 36 days and no more: no hold of 36 days or
	// longer can be judged.
	want := ecosystemReport{Ecosystem: "Go", Hold: "168h0m0s", Entries: 3, Dated: 2, Undated: 1, Unlisted: 1, Share: 0.5,
		Thin: true, ProposedDays: 0, SearchedDays: 35, Note: "thin, so this month moves nothing"}
	if g != want {
		t.Errorf("Go\n got %+v\nwant %+v", g, want)
	}
	if len(env.reg.sinceGot) == 0 || env.reg.sinceGot[0] != "2026-09-01T00:00:00Z" {
		t.Errorf("the index was read from %v, want 2026-09-01, the goWindow before the month", env.reg.sinceGot)
	}
	for _, p := range env.reg.asked {
		if strings.Contains(p, "/@v/") && !strings.HasPrefix(p, "/cached-only/") {
			t.Errorf("asked the proxy for %s, which would have it fetch a malicious version", p)
		}
	}
}

func TestARegistryThatKeepsFailingFailsTheRun(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	env.reg.fail = true
	r := env.newRun()
	_, err := r.run(context.Background(), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Now())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("run against a failing registry: %v, want it to fail naming the answer", err)
	}
	if n := len(env.reg.asked); n != 3 {
		t.Errorf("asked %d times, want the first package three times and then stop", n)
	}
}

func TestAReplayedMonthPastTheBandPostsItsAlert(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	path, _ := env.files()
	if err := holdLagMain([]string{path, "2026-10"}, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if len(env.am.alerts) != 1 {
		t.Fatalf("alerts %v, want npm's", env.am.alerts)
	}
	a := env.am.alerts[0]
	labels := a["labels"].(map[string]any)
	for k, want := range map[string]string{"alertname": "ViaMarisHoldLagOutOfBand", "severity": "ticket", "ecosystem": "npm", "month": "2026-10"} {
		if labels[k] != want {
			t.Errorf("label %s = %v, want %s", k, labels[k], want)
		}
	}
	ann := a["annotations"].(map[string]any)
	wantContains(t, ann["summary"].(string), "2 of 6 (33.3%)", "720h0m0s hold", "15.0% to 25.0%")
	wantContains(t, ann["description"].(string), "70 days is the shortest hold that leaves 20.0% or less")
	starts, _ := time.Parse(time.RFC3339, a["startsAt"].(string))
	ends, _ := time.Parse(time.RFC3339, a["endsAt"].(string))
	if ends.Sub(starts) != 744*time.Hour {
		t.Errorf("alert lasts %s, want alertFor", ends.Sub(starts))
	}
}

func TestAMonthInsideTheBandPostsNothing(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	// Without g, one of five dated versions passes the hold: 20%.
	delete(env.reg.npm, "g")
	path, _ := env.files()
	if err := holdLagMain([]string{path, "2026-10"}, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if len(env.am.alerts) != 0 {
		t.Errorf("alerts %v, want none", env.am.alerts)
	}
}

func TestAnUnpostedAlertFailsTheRun(t *testing.T) {
	env := newHoldLagEnv(t)
	env.october()
	env.am.down = true
	path, _ := env.files()
	if err := holdLagMain([]string{path, "2026-10"}, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "posting 1 alerts") {
		t.Fatalf("run with Alertmanager down: %v", err)
	}
}

func TestARunOnTheFirstReadsTheMonthBefore(t *testing.T) {
	for now, want := range map[string]string{
		"2026-11-01T03:00:00Z": "2026-10",
		"2027-01-01T03:00:00Z": "2026-12",
		"2026-03-31T23:59:59Z": "2026-02",
	} {
		if got := previousMonth(at(now)).Format("2006-01"); got != want {
			t.Errorf("previousMonth(%s) = %s, want %s", now, got, want)
		}
	}
}

func TestExampleHoldLagConfigLoads(t *testing.T) {
	cfg, err := loadHoldLagConfig("hold-lag.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinDated != 100 || cfg.Target != 0.2 || cfg.Low != 0.15 || cfg.High != 0.25 || cfg.GoWindow.Duration != 30*day {
		t.Errorf("loaded %+v", cfg)
	}
	setExampleKeys(t)
	if _, err := readHoldLagGateway("config.example.json", http.DefaultClient); err != nil {
		t.Errorf("the example gateway configuration: %v", err)
	}
}

func TestHoldLagConfigRefusesABandThatDoesNotHoldTheTarget(t *testing.T) {
	c := HoldLagConfig{GatewayConfig: "x", Alertmanager: "http://am:9093", AlertFor: Duration{time.Hour}, Target: 0.3, Low: 0.15, High: 0.25, MinDated: 1, MaxHoldDays: 1, GoWindow: Duration{time.Hour}}
	if err := c.validate(); err == nil {
		t.Error("a target above the band validated")
	}
}
