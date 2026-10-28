package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"
)

type fakeNPM struct {
	srv      *httptest.Server
	packages map[string]map[string]time.Duration
	tags     map[string]map[string]string
	base     string
}

func newFakeNPM(t *testing.T) *fakeNPM {
	f := &fakeNPM{packages: map[string]map[string]time.Duration{}, tags: map[string]map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if name, file, ok := strings.Cut(p, "/-/"); ok {
			if _, known := f.packages[name]; known {
				w.Write([]byte("tarball " + file))
				return
			}
		}
		if p == "-/npm/v1/security/advisories/bulk" {
			w.Write([]byte(`{}`))
			return
		}
		versions, ok := f.packages[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{"name": p, "versions": map[string]any{}, "time": map[string]any{}, "dist-tags": f.tags[p]}
		base := f.base
		if base == "" {
			base = f.srv.URL
		}
		for v, age := range versions {
			doc["versions"].(map[string]any)[v] = map[string]any{
				"name": p, "version": v,
				"dist": map[string]any{"tarball": base + "/" + p + "/-/" + path.Base(p) + "-" + v + ".tgz"},
			}
			if age >= 0 {
				doc["time"].(map[string]any)[v] = ago(age)
			}
		}
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func npmUpstream(url string) Upstream {
	return Upstream{Name: "npm", Ecosystem: "npm", URL: url, Hold: Duration{7 * day}, Advisories: "malicious"}
}

// The acceptance case: an install of a version listed as malicious fails
// through the gateway, naming the package and the advisory.
func TestNPMTarballOfMaliciousVersionIsRefusedNamingTheAdvisory(t *testing.T) {
	reg := newFakeNPM(t)
	reg.packages["fsevents"] = map[string]time.Duration{"1.2.4": 2000 * day, "1.2.3": 2000 * day}
	env := newTestEnv(t, npmUpstream(reg.srv.URL))
	env.osv.set(t, "npm", osvJSON("MAL-2023-462", "npm", "fsevents", []string{"1.2.4"}))
	env.loadAdvisories()

	status, body := env.get("/npm/fsevents/-/fsevents-1.2.4.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}
	var msg struct{ Error string }
	json.Unmarshal([]byte(body), &msg)
	if msg.Error != "via-maris refused fsevents@1.2.4: listed as malicious by MAL-2023-462" {
		t.Errorf("refusal %q", msg.Error)
	}
	rec := env.lastRecord()
	if rec.Served || rec.Package != "fsevents" || rec.Version != "1.2.4" || rec.Kind != "artifact" || rec.Reason != "listed as malicious by MAL-2023-462" || rec.Client == "" {
		t.Errorf("record %+v", rec)
	}
	if p, err := time.Parse(time.RFC3339Nano, rec.Published); err != nil || time.Since(p).Round(time.Hour) != 2000*day {
		t.Errorf("published %q, want the upstream's time for 1.2.4, 2000 days ago", rec.Published)
	}

	status, body = env.get("/npm/fsevents/-/fsevents-1.2.3.tgz")
	if status != http.StatusOK || body != "tarball fsevents-1.2.3.tgz" {
		t.Errorf("unlisted version: %d %q", status, body)
	}
}

func TestNPMPackumentMarksRefusedVersionsAndMovesTagsWithinTheirLine(t *testing.T) {
	reg := newFakeNPM(t)
	reg.packages["body-parser"] = map[string]time.Duration{"1.20.8": 100 * day, "1.20.9": day, "2.3.0": 50 * day, "2.4.0": day}
	reg.tags["body-parser"] = map[string]string{"latest": "2.4.0", "latest-1.x": "1.20.9"}
	reg.packages["@scope/held"] = map[string]time.Duration{"1.0.0": day}
	reg.tags["@scope/held"] = map[string]string{"latest": "1.0.0"}
	env := newTestEnv(t, npmUpstream(reg.srv.URL))
	env.loadAdvisories()

	status, body := env.get("/npm/body-parser")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var doc struct {
		Tags     map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Deprecated string
			Dist       struct{ Tarball string }
		}
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Tags["latest"] != "2.3.0" || doc.Tags["latest-1.x"] != "1.20.8" {
		t.Errorf("dist-tags %v, want latest 2.3.0 and latest-1.x 1.20.8", doc.Tags)
	}
	wantContains(t, doc.Versions["1.20.9"].Deprecated, "via-maris refused body-parser@1.20.9: published ", "inside the 168h0m0s release-age hold until ")
	if doc.Versions["1.20.8"].Deprecated != "" {
		t.Errorf("1.20.8 deprecated: %q", doc.Versions["1.20.8"].Deprecated)
	}
	if want := env.srv.URL + "/npm/body-parser/-/body-parser-1.20.8.tgz"; doc.Versions["1.20.8"].Dist.Tarball != want {
		t.Errorf("tarball %q, want %q", doc.Versions["1.20.8"].Dist.Tarball, want)
	}

	// A scoped name reaches the upstream escaped; a tag with no allowed
	// version below it is dropped.
	status, body = env.get("/npm/" + url.PathEscape("@scope/held"))
	if status != http.StatusOK {
		t.Fatalf("scoped: %d %s", status, body)
	}
	doc.Tags = nil
	json.Unmarshal([]byte(body), &doc)
	if _, ok := doc.Tags["latest"]; ok {
		t.Errorf("dist-tags %v, want latest dropped", doc.Tags)
	}
}

func TestNPMRefusesWhatItCannotCheck(t *testing.T) {
	reg := newFakeNPM(t)
	reg.packages["left-pad"] = map[string]time.Duration{"1.3.0": 1000 * day, "0.0.1": -1}
	env := newTestEnv(t, npmUpstream(reg.srv.URL))

	status, body := env.get("/npm/left-pad/-/left-pad-1.3.0.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("before advisories load: %d %s", status, body)
	}
	wantContains(t, body, "advisory data for npm has not loaded")

	env.loadAdvisories()
	status, body = env.get("/npm/left-pad/-/left-pad-0.0.1.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("no publication time: %d", status)
	}
	wantContains(t, body, "the upstream gives no publication time")
	if rec := env.lastRecord(); rec.Published != "" {
		t.Errorf("published %q for a version the upstream gives no time for", rec.Published)
	}

	status, body = env.get("/npm/left-pad/-/other-9.9.9.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("unlisted tarball: %d", status)
	}
	wantContains(t, body, "no version of the package lists this tarball")

	if status, _ = env.get("/npm/missing"); status != http.StatusNotFound {
		t.Errorf("unknown package: %d, want the upstream's 404", status)
	}
}

func TestNPMForwardsOnlyAuditAndPing(t *testing.T) {
	reg := newFakeNPM(t)
	env := newTestEnv(t, npmUpstream(reg.srv.URL))
	resp, err := http.Post(env.srv.URL+"/npm/-/npm/v1/security/advisories/bulk", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("audit: %d", resp.StatusCode)
	}
	if status, _ := env.get("/npm/-/user/org.couchdb.user:someone"); status != http.StatusNotFound {
		t.Errorf("login endpoint: %d, want 404", status)
	}
	resp, err = http.Post(env.srv.URL+"/npm/left-pad", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("publish: %d, want 405", resp.StatusCode)
	}
}

func TestHighestSemverBelow(t *testing.T) {
	vs := []string{"1.0.0", "1.2.0", "2.0.0-rc.1", "1.10.0", "bogus"}
	for _, c := range []struct {
		ceiling     string
		releaseOnly bool
		want        string
	}{
		{"2.0.0", true, "1.10.0"},
		{"2.0.0", false, "2.0.0-rc.1"},
		{"1.2.0", true, "1.0.0"},
		{"1.0.0", true, ""},
	} {
		if got := highestSemverBelow(vs, c.ceiling, c.releaseOnly); got != c.want {
			t.Errorf("highestSemverBelow(%s, %v) = %q, want %q", c.ceiling, c.releaseOnly, got, c.want)
		}
	}
}
