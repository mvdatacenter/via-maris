package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAptSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 25, 8, 37, 4, 0, time.UTC)
	if got := aptSnapshot(now, 7*day); got != "20261018T000000Z" {
		t.Errorf("aptSnapshot = %s", got)
	}
	if got := aptSnapshot(now, 8*time.Hour+37*time.Minute+5*time.Second); got != "20261024T000000Z" {
		t.Errorf("aptSnapshot across midnight = %s", got)
	}
}

func TestAptServesTheArchiveFromTheSnapshotOneHoldAgo(t *testing.T) {
	var asked string
	snapshot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Write([]byte("deb"))
	}))
	t.Cleanup(snapshot.Close)
	env := newTestEnv(t, Upstream{Name: "apt", Ecosystem: "apt", URL: snapshot.URL, Hold: Duration{7 * day}})

	status, body := env.get("/apt/ubuntu/pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb")
	if status != http.StatusOK || body != "deb" {
		t.Fatalf("%d %q", status, body)
	}
	if want := "/ubuntu/" + aptSnapshot(time.Now(), 7*day) + "/pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb"; asked != want {
		t.Errorf("asked %s, want %s", asked, want)
	}
	if rec := env.lastRecord(); rec.Kind != "artifact" || rec.Package != "curl" || rec.Version != "8.5.0-2ubuntu10.6" || !rec.Served {
		t.Errorf("record %+v", rec)
	}

	for _, p := range []string{"/apt/ubuntu/etc/passwd", "/apt/ubuntu/dists/../../x", "/apt/Bad/dists/noble/InRelease", "/apt/ubuntu"} {
		if status, _ := env.get(p); status != http.StatusNotFound && status != http.StatusMovedPermanently {
			t.Errorf("%s: %d", p, status)
		}
	}
}

func TestPinnedFileIsServedOnlyWhenItsDigestMatches(t *testing.T) {
	content := []byte("go1.27.3.linux-amd64.tar.gz bytes")
	sum := sha256.Sum256(content)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	t.Cleanup(origin.Close)
	env := newTestEnv(t, Upstream{Name: "files", Ecosystem: "files", Pinned: []PinnedFile{
		{Name: "go/go1.27.3.linux-amd64.tar.gz", URL: origin.URL + "/go.tgz", SHA256: hex.EncodeToString(sum[:])},
		{Name: "tampered", URL: origin.URL + "/go.tgz", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
	}})

	status, body := env.get("/files/go/go1.27.3.linux-amd64.tar.gz")
	if status != http.StatusOK || body != string(content) {
		t.Errorf("pinned: %d %q", status, body)
	}
	status, body = env.get("/files/tampered")
	if status != http.StatusForbidden {
		t.Errorf("tampered: %d", status)
	}
	wantContains(t, body, "via-maris refused tampered: its bytes hash to sha256:"+hex.EncodeToString(sum[:]))
	if rec := env.lastRecord(); rec.Served || rec.Version != "sha256:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("record %+v", rec)
	}
	if status, _ := env.get("/files/unnamed"); status != http.StatusNotFound {
		t.Errorf("unnamed: %d", status)
	}
}
