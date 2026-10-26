package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeGoProxy is a module proxy and its index. Each version has the time
// the proxy first served it; a version with a zero time is one the proxy has
// not fetched yet but can.
type fakeGoProxy struct {
	proxy, index, sumdb *httptest.Server
	versions            map[string]time.Time // "module@version", unescaped
}

func newFakeGoProxy(t *testing.T) *fakeGoProxy {
	f := &fakeGoProxy{versions: map[string]time.Time{}}
	f.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		cachedOnly := false
		if rest, ok := strings.CutPrefix(p, "cached-only/"); ok {
			p, cachedOnly = rest, true
		}
		modEsc, tail, _ := strings.Cut(p, "/@")
		mod, _ := unescapeModule(modEsc)
		switch {
		case tail == "v/list":
			for k, first := range f.versions {
				if m, v, _ := strings.Cut(k, "@"); m == mod && !first.IsZero() {
					fmt.Fprintln(w, v)
				}
			}
		case strings.HasPrefix(tail, "v/"):
			file := strings.TrimPrefix(tail, "v/")
			ver := file[:strings.LastIndex(file, ".")]
			first, ok := f.versions[mod+"@"+ver]
			if !ok || (cachedOnly && first.IsZero()) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, "%s %s", mod, file)
		default:
			http.NotFound(w, r)
		}
	}))
	f.index = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
		for k, first := range f.versions {
			if first.IsZero() || first.Before(since) {
				continue
			}
			m, v, _ := strings.Cut(k, "@")
			json.NewEncoder(w).Encode(map[string]any{"Path": m, "Version": v, "Timestamp": first})
		}
	}))
	f.sumdb = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "sumdb %s", r.URL.Path)
	}))
	t.Cleanup(f.proxy.Close)
	t.Cleanup(f.index.Close)
	t.Cleanup(f.sumdb.Close)
	return f
}

func goEnv(t *testing.T, f *fakeGoProxy, entries ...string) *testEnv {
	t.Helper()
	env := newTestEnv(t, Upstream{
		Name: "go", Ecosystem: "Go", URL: f.proxy.URL, Index: f.index.URL, SumDB: f.sumdb.URL,
		IndexPoll: Duration{time.Minute}, IndexMaxAge: Duration{5 * time.Minute},
		Hold: Duration{7 * day}, Advisories: "malicious",
	})
	env.osv.set(t, "Go", entries...)
	env.loadAdvisories()
	return env
}

func loadIndex(t *testing.T, env *testEnv) *goIndex {
	t.Helper()
	ix := env.g.goIdx["go"]
	ix.begin(time.Now())
	if err := ix.read(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestGoRefusesWhileTheIndexWindowIsNotCurrent(t *testing.T) {
	f := newFakeGoProxy(t)
	env := goEnv(t, f)
	status, body := env.get("/go/example.com/mod/@v/list")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", status, body)
	}
	wantContains(t, body, "the Go index window has not loaded")
	if got := env.g.notReady(); len(got) != 1 || got[0] != "go index" {
		t.Errorf("notReady %v", got)
	}

	ix := loadIndex(t, env)
	if got := env.g.notReady(); len(got) != 0 {
		t.Errorf("notReady after loading %v", got)
	}
	ix.mu.Lock()
	ix.polled = time.Now().Add(-6 * time.Minute)
	ix.mu.Unlock()
	_, body = env.get("/go/example.com/mod/@v/list")
	wantContains(t, body, "the Go index was last read 6m0s ago, past the 5m0s bound")
}

func TestGoChecksEachVersionByWhenTheProxyFirstServedIt(t *testing.T) {
	f := newFakeGoProxy(t)
	f.versions["example.com/Mod@v1.0.0"] = time.Now().Add(-30 * day)  // before the window
	f.versions["example.com/Mod@v1.1.0"] = time.Now().Add(-time.Hour) // inside the hold
	f.versions["example.com/Mod@v1.2.0"] = time.Time{}                // never fetched yet
	f.versions["github.com/boltdb-go/bolt@v1.3.1"] = time.Now().Add(-30 * day)
	f.versions["github.com/boltdb-go/bolt@v1.3.2"] = time.Now().Add(-time.Hour)
	env := goEnv(t, f, osvJSON("MAL-2025-2545", "Go", "github.com/boltdb-go/bolt", []string{"v1.3.1", "v1.3.2"}))
	loadIndex(t, env)

	status, body := env.get("/go/example.com/!mod/@v/v1.0.0.zip")
	if status != http.StatusOK || body != "example.com/Mod v1.0.0.zip" {
		t.Errorf("old version: %d %q", status, body)
	}
	if p := env.lastRecord().Published; p != "" {
		t.Errorf("old version published %q, want none: the window start only bounds it", p)
	}
	status, body = env.get("/go/example.com/!mod/@v/v1.1.0.info")
	if status != http.StatusForbidden {
		t.Errorf("version inside the hold: %d", status)
	}
	wantContains(t, body, "via-maris refused example.com/Mod@v1.1.0: published ", "release-age hold")
	if p, err := time.Parse(time.RFC3339Nano, env.lastRecord().Published); err != nil || time.Since(p).Round(time.Hour) != time.Hour {
		t.Errorf("version inside the hold published %v, want its index time, an hour ago", p)
	}
	status, body = env.get("/go/example.com/!mod/@v/v1.2.0.mod")
	if status != http.StatusForbidden {
		t.Errorf("version first fetched now: %d", status)
	}
	wantContains(t, body, "release-age hold")
	if p, err := time.Parse(time.RFC3339Nano, env.lastRecord().Published); err != nil || time.Since(p).Round(time.Hour) != 0 {
		t.Errorf("version first fetched now published %v", p)
	}
	status, body = env.get("/go/github.com/boltdb-go/bolt/@v/v1.3.1.info")
	if status != http.StatusForbidden || !strings.Contains(body, "listed as malicious by MAL-2025-2545") {
		t.Errorf("listed version: %d %q", status, body)
	}
	if p := env.lastRecord().Published; p != "" {
		t.Errorf("listed version before the window published %q, want none", p)
	}
	status, body = env.get("/go/github.com/boltdb-go/bolt/@v/v1.3.2.info")
	if status != http.StatusForbidden || !strings.Contains(body, "listed as malicious by MAL-2025-2545") {
		t.Errorf("listed version inside the window: %d %q", status, body)
	}
	if p, err := time.Parse(time.RFC3339Nano, env.lastRecord().Published); err != nil || time.Since(p).Round(time.Hour) != time.Hour {
		t.Errorf("listed version inside the window published %v, want its index time, an hour ago", p)
	}

	// A version the proxy does not have passes its 404 on, so the go
	// command tries the next path.
	status, _ = env.get("/go/example.com/!mod/@v/v9.9.9.info")
	if status != http.StatusNotFound {
		t.Errorf("missing version: %d", status)
	}
	if rec := env.lastRecord(); rec.Kind != "missing" || rec.Served {
		t.Errorf("record %+v", rec)
	}

	status, body = env.get("/go/example.com/!mod/@v/list")
	if status != http.StatusOK || strings.TrimSpace(body) != "v1.0.0" {
		t.Errorf("list: %d %q, want v1.0.0 alone", status, body)
	}
}

func TestGoSumDBPassesThrough(t *testing.T) {
	f := newFakeGoProxy(t)
	env := goEnv(t, f)
	host := strings.TrimPrefix(f.sumdb.URL, "http://")
	if status, _ := env.get("/go/sumdb/" + host + "/supported"); status != http.StatusOK {
		t.Errorf("supported: %d", status)
	}
	status, body := env.get("/go/sumdb/" + host + "/lookup/example.com/mod@v1.0.0")
	if status != http.StatusOK || body != "sumdb /lookup/example.com/mod@v1.0.0" {
		t.Errorf("lookup: %d %q", status, body)
	}
	if status, _ := env.get("/go/sumdb/sum.example.invalid/lookup/x@v1.0.0"); status != http.StatusNotFound {
		t.Errorf("another checksum database: %d", status)
	}
}

func TestModuleEscaping(t *testing.T) {
	if got, ok := unescapeModule("github.com/!azure/go"); !ok || got != "github.com/Azure/go" {
		t.Errorf("unescape: %q %v", got, ok)
	}
	for _, bad := range []string{"github.com/Azure", "trailing!", "!!x"} {
		if _, ok := unescapeModule(bad); ok {
			t.Errorf("unescapeModule(%q) accepted", bad)
		}
	}
	if got := escapeVersion("v1.0.0-RC1"); got != "v1.0.0-!r!c1" {
		t.Errorf("escapeVersion: %q", got)
	}
}
