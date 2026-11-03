package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFile struct {
	body     string
	modified time.Time
}

type fakeMaven struct {
	mu    sync.Mutex
	files map[string]fakeFile
	heads map[string]int
	srv   *httptest.Server
	port  string
}

func newFakeMaven(t *testing.T) *fakeMaven {
	f := &fakeMaven{files: map[string]fakeFile{}, heads: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		file, ok := f.files[r.URL.Path]
		if r.Method == http.MethodHead {
			f.heads[r.URL.Path]++
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !file.modified.IsZero() {
			w.Header().Set("Last-Modified", file.modified.UTC().Format(http.TimeFormat))
		}
		io.WriteString(w, file.body)
	}))
	t.Cleanup(f.srv.Close)
	f.port = f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:]
	return f
}

func (f *fakeMaven) put(path, body string, age time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mod time.Time
	if age > 0 {
		mod = time.Now().Add(-age)
	}
	f.files[path] = fakeFile{body, mod}
}

func (f *fakeMaven) release(root, version string, age time.Duration) {
	dir := root + "/org/example/lib/" + version + "/lib-" + version
	f.put(dir+".pom", "pom "+version, age)
	f.put(dir+".jar", "jar "+version, age)
}

func (f *fakeMaven) url(host, path string) string { return "http://" + host + ":" + f.port + path }

const libMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.example</groupId>
  <artifactId>lib</artifactId>
  <versioning>
    <latest>1.3.0-rc1</latest>
    <release>1.3.0-rc1</release>
    <versions>
      <version>0.9.0</version>
      <version>1.0.0</version>
      <version>1.1.0</version>
      <version>1.2.0</version>
      <version>1.3.0-rc1</version>
    </versions>
    <lastUpdated>20261101000000</lastUpdated>
  </versioning>
</metadata>
`

func mavenUpstream(name, url string) Upstream {
	return Upstream{Name: name, Ecosystem: "Maven", URL: url, Hold: Duration{30 * day}, Advisories: "malicious"}
}

func newMavenEnv(t *testing.T) (*testEnv, *fakeMaven) {
	t.Helper()
	f := newFakeMaven(t)
	f.put("/maven2/org/example/lib/maven-metadata.xml", libMetadata, 0)
	f.release("/maven2", "0.9.0", 900*day)
	f.release("/maven2", "1.0.0", 400*day)
	f.release("/maven2", "1.1.0", 100*day)
	f.release("/maven2", "1.2.0", day)
	f.release("/maven2", "1.3.0-rc1", day)
	env := newTestEnv(t, mavenUpstream("central", f.srv.URL+"/maven2"))
	env.osv.set(t, "Maven", osvJSON("MAL-2025-0001", "Maven", "org.example:lib", []string{"0.9.0"}))
	env.loadAdvisories()
	return env, f
}

func TestMavenMetadataListsOnlyServedVersions(t *testing.T) {
	env, _ := newMavenEnv(t)
	status, body := env.get("/central/org/example/lib/maven-metadata.xml")
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	want := strings.NewReplacer(
		"<latest>1.3.0-rc1</latest>", "<latest>1.1.0</latest>",
		"<release>1.3.0-rc1</release>", "<release>1.1.0</release>",
		"      <version>0.9.0</version>\n", "",
		"      <version>1.2.0</version>\n", "",
		"      <version>1.3.0-rc1</version>\n", "",
	).Replace(libMetadata)
	if body != want {
		t.Errorf("metadata\n%s\nwant\n%s", body, want)
	}
	if r := env.lastRecord(); r.Kind != "metadata" || r.Package != "org.example:lib" || r.Reason != "3 of 5 versions refused" {
		t.Errorf("record %+v", r)
	}
	for ext, sum := range map[string]string{
		".sha1":   fmt.Sprintf("%x", sha1.Sum([]byte(want))),
		".sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(want))),
	} {
		if status, got := env.get("/central/org/example/lib/maven-metadata.xml" + ext); status != http.StatusOK || got != sum {
			t.Errorf("%s: %d %q, want the checksum of the rewritten listing %s", ext, status, got, sum)
		}
	}
}

func TestMavenMetadataDropsLatestWhenNothingIsServed(t *testing.T) {
	doc := "<metadata><versioning>\n  <latest>2.0</latest>\n  <release>2.0</release>\n  <versions>\n    <version>2.0</version>\n  </versions>\n</versioning></metadata>"
	got := rewriteMavenMetadata(doc, map[string]bool{"2.0": true}, nil)
	if want := "<metadata><versioning>\n  <versions>\n  </versions>\n</versioning></metadata>"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = rewriteMavenMetadata("<release>2.0</release><versions><version>1.0-SNAPSHOT</version><version>2.0</version></versions>", map[string]bool{"2.0": true}, []string{"1.0-SNAPSHOT"})
	if want := "<versions><version>1.0-SNAPSHOT</version></versions>"; got != want {
		t.Errorf("a snapshot became the release: %q", got)
	}
}

// mavenGet fetches with Go's client, whose Status carries the reason phrase
// Gradle prints.
func mavenGet(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	return fetchBody(t, c, u)
}

func TestMavenArtifactsAreCheckedByTheirVersion(t *testing.T) {
	env, f := newMavenEnv(t)
	base := env.srv.URL + "/central/org/example/lib/"

	resp, body := mavenGet(t, http.DefaultClient, base+"1.1.0/lib-1.1.0.jar")
	if resp.StatusCode != http.StatusOK || body != "jar 1.1.0" {
		t.Errorf("served version: %d %q", resp.StatusCode, body)
	}
	if r := env.lastRecord(); r.Kind != "artifact" || !r.Served || r.Ecosystem != "Maven" || r.Package != "org.example:lib" || r.Version != "1.1.0" || r.Published == "" {
		t.Errorf("record %+v", r)
	}
	mavenGet(t, http.DefaultClient, base+"1.1.0/lib-1.1.0.pom")
	if n := f.heads["/maven2/org/example/lib/1.1.0/lib-1.1.0.pom"]; n != 1 {
		t.Errorf("the .pom was read %d times for its date, want once", n)
	}

	resp, body = mavenGet(t, http.DefaultClient, base+"1.2.0/lib-1.2.0.pom")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("held version: %d %q", resp.StatusCode, body)
	}
	wantContains(t, resp.Status, "403 via-maris refused org.example:lib@1.2.0: published ", "inside the 720h0m0s release-age hold until ")
	wantContains(t, body, "via-maris refused org.example:lib@1.2.0: published ")

	resp, _ = mavenGet(t, http.DefaultClient, base+"0.9.0/lib-0.9.0.jar")
	wantContains(t, resp.Status, "403 via-maris refused org.example:lib@0.9.0: listed as malicious by MAL-2025-0001")

	resp, body = mavenGet(t, http.DefaultClient, base+"2.0.0/lib-2.0.0.pom")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a version the upstream lacks: %d %q, want its 404 so the build tries its next repository", resp.StatusCode, body)
	}

	resp, _ = mavenGet(t, http.DefaultClient, base+"1.1.0/other-1.1.0.jar")
	wantContains(t, resp.Status, "403 via-maris refused org/example/lib/1.1.0/other-1.1.0.jar: its file name does not start with lib-1.1.0")

	f.put("/maven2/org/example/lib/1.4.0/lib-1.4.0.pom", "pom", 0)
	resp, _ = mavenGet(t, http.DefaultClient, base+"1.4.0/lib-1.4.0.pom")
	wantContains(t, resp.Status, "403 via-maris refused org.example:lib@1.4.0: the upstream gives no publication time")

	resp, _ = mavenGet(t, http.DefaultClient, env.srv.URL+"/central/org/../lib/1.1.0/lib-1.1.0.jar")
	if resp.StatusCode == http.StatusOK {
		t.Error("a path climbing out of the repository was served")
	}
}

func TestMavenExceptionAdmitsAHeldVersion(t *testing.T) {
	env, _ := newMavenEnv(t)
	env.g.cfg.Upstreams[0].Exceptions = []Exception{{Package: "org.example:lib", Version: "1.2.0", Reason: "a fix", Reviewed: "https://example.test/1", Expires: Date{time.Now().Add(day)}}}
	resp, body := mavenGet(t, http.DefaultClient, env.srv.URL+"/central/org/example/lib/1.2.0/lib-1.2.0.jar")
	if resp.StatusCode != http.StatusOK || body != "jar 1.2.0" {
		t.Errorf("%d %q", resp.StatusCode, body)
	}
}

type mavenByNameEnv struct {
	*byNameEnv
	maven   *fakeMaven
	mavenCA *testCA
	dir     string
	leaf    time.Time
	dist    []byte
	held    string
}

var mavenNames = []string{"central.test", "google.test", "dist.test"}

func newMavenByNameEnv(t *testing.T) *mavenByNameEnv {
	t.Helper()
	f := newFakeMaven(t)
	f.put("/maven2/org/example/lib/maven-metadata.xml", libMetadata, 0)
	f.release("/maven2", "1.1.0", 100*day)
	f.release("/maven2", "1.2.0", day)
	f.put("/android/repository/repository2-3.xml", "<sdk:sdk-repository/>", 0)
	dist := []byte("gradle distribution bytes")
	f.put("/distributions/gradle-9.3.1-bin.zip", string(dist), 0)
	sum := sha256.Sum256(dist)
	held := t.TempDir()
	files := Upstream{Name: "gradle-files", Ecosystem: "files", Held: held, Pinned: []PinnedFile{
		{Name: "gradle-9.3.1-bin.zip", URL: f.url("dist.test", "/distributions/gradle-9.3.1-bin.zip"), SHA256: hex.EncodeToString(sum[:])},
	}}
	env := &mavenByNameEnv{
		byNameEnv: newByNameEnv(t, map[string]time.Duration{"boto3-1.0.0-py3-none-any.whl": 100 * day},
			mavenUpstream("central", f.url("central.test", "/maven2")),
			mavenUpstream("google", f.url("google.test", "/dl/android/maven2")),
			files),
		maven: f, dist: dist, held: held,
	}
	env.g.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if strings.HasSuffix(host, ".test") {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	env.mavenCA = newTestCA(t, append(mavenNames, "plugins.test")...)
	env.dir = t.TempDir()
	env.leaf = env.mavenCA.writeLeaf(t, env.dir, 7, 25*day, mavenNames...)
	env.g.cfg.ByName.Maven = &MavenByName{
		Upstreams: []string{"central", "google"},
		Files:     "gradle-files",
		Listings:  []string{f.url("google.test", "/android/repository")},
		Cert:      filepath.Join(env.dir, "tls.crt"), Key: filepath.Join(env.dir, "tls.key"), CA: filepath.Join(env.dir, "ca.crt"),
	}
	if err := env.g.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	env.osv.set(t, "Maven")
	env.loadAdvisories()
	env.g.byName.srv.Close()
	env.g.byName = newByName(env.g, env.g.cfg.ByName)
	env.srv.Config.Handler = env.g.handler()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.tlsAddr = ln.Addr().String()
	go env.g.byName.serveTLS(ln)
	t.Cleanup(func() { env.g.byName.srv.Close() })
	return env
}

func (env *mavenByNameEnv) mappedMaven() *http.Client {
	c := env.mapped()
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = env.mavenCA.pool
	return c
}

func (env *mavenByNameEnv) clients() map[string]*http.Client {
	out := map[string]*http.Client{}
	for name, c := range map[string]*http.Client{"CONNECT": env.proxied(), "mapped": env.mapped()} {
		c.Transport.(*http.Transport).TLSClientConfig.RootCAs = env.mavenCA.pool
		out[name] = c
	}
	return out
}

func TestByNameMavenServesRepositoriesPinnedFilesAndListings(t *testing.T) {
	env := newMavenByNameEnv(t)
	env.g.held["gradle-files"].fetchMissing(context.Background())
	for route, c := range env.clients() {
		t.Run(route, func(t *testing.T) {
			resp, body := fetchBody(t, c, "https://central.test/maven2/org/example/lib/1.1.0/lib-1.1.0.jar")
			if resp.StatusCode != http.StatusOK || body != "jar 1.1.0" {
				t.Errorf("served version: %d %q", resp.StatusCode, body)
			}
			if resp.Proto != "HTTP/1.1" {
				t.Errorf("proto %s, want HTTP/1.1 so a refusal carries its reason phrase", resp.Proto)
			}
			resp, _ = fetchBody(t, c, "https://central.test/maven2/org/example/lib/1.2.0/lib-1.2.0.pom")
			wantContains(t, resp.Status, "403 via-maris refused org.example:lib@1.2.0: published ")
			if r := env.lastRecord(); r.Upstream != "central" || r.Served {
				t.Errorf("record %+v", r)
			}
			resp, _ = fetchBody(t, c, "https://google.test/dl/android/maven2/org/example/lib/1.1.0/lib-1.1.0.pom")
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("a version the other repository lacks: %s, want 404", resp.Status)
			}
			resp, body = fetchBody(t, c, "https://central.test/maven2/org/example/lib/maven-metadata.xml")
			if resp.StatusCode != http.StatusOK || strings.Contains(body, "<version>1.2.0</version>") {
				t.Errorf("metadata %d %s", resp.StatusCode, body)
			}

			resp, body = fetchBody(t, c, "https://dist.test/distributions/gradle-9.3.1-bin.zip")
			if resp.StatusCode != http.StatusOK || body != string(env.dist) {
				t.Errorf("pinned distribution: %d %q", resp.StatusCode, body)
			}
			if r := env.lastRecord(); r.Upstream != "gradle-files" || !r.Served || r.Package != "gradle-9.3.1-bin.zip" {
				t.Errorf("record %+v", r)
			}
			resp, _ = fetchBody(t, c, "https://dist.test/distributions/gradle-9.4.0-bin.zip")
			wantContains(t, resp.Status, "403 via-maris refused https://dist.test/distributions/gradle-9.4.0-bin.zip: it is not a pinned file")

			resp, body = fetchBody(t, c, "https://google.test/android/repository/repository2-3.xml")
			if resp.StatusCode != http.StatusOK || body != "<sdk:sdk-repository/>" {
				t.Errorf("listing: %d %q", resp.StatusCode, body)
			}
			resp, _ = fetchBody(t, c, "https://google.test/android/repository/platform-37_r01.zip")
			wantContains(t, resp.Status, "403 via-maris refused https://google.test/android/repository/platform-37_r01.zip")
			resp, _ = fetchBody(t, c, "https://google.test/somewhere/else.xml")
			wantContains(t, resp.Status, "403 via-maris refused https://google.test/somewhere/else.xml")
		})
	}
	_, metrics := env.get("/metrics")
	wantContains(t, metrics,
		fmt.Sprintf("via_maris_tls_expiry_timestamp_seconds{certificate=\"maven-leaf\"} %d\n", env.leaf.Unix()),
		fmt.Sprintf("via_maris_tls_expiry_timestamp_seconds{certificate=\"maven-ca\"} %d\n", env.mavenCA.cert.NotAfter.Unix()),
		"via_maris_pinned_unheld{upstream=\"gradle-files\"} 0\n")
}

func TestByNameMavenConnectReachesTheMavenNamesAlone(t *testing.T) {
	env := newMavenByNameEnv(t)
	connect := func(target string) *http.Response {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(env.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, h := range mavenNames {
		if resp := connect(h + ":443"); resp.StatusCode != http.StatusOK {
			t.Errorf("CONNECT %s: %s", h, resp.Status)
		}
	}
	resp := connect("plugins.test:443")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT plugins.test: %s", resp.Status)
	}
	wantContains(t, string(b), "central.test:443, google.test:443 and dist.test:443 alone")
}

func TestHeldFilesRefuseUntilTheirBytesMatch(t *testing.T) {
	env := newMavenByNameEnv(t)
	h := env.g.held["gradle-files"]
	env.maven.put("/distributions/gradle-9.3.1-bin.zip", "tampered", 0)
	h.fetchMissing(context.Background())
	resp, _ := fetchBody(t, env.mappedMaven(), "https://dist.test/distributions/gradle-9.3.1-bin.zip")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an unheld file: %s", resp.Status)
	}
	wantContains(t, resp.Status, "via-maris refused gradle-9.3.1-bin.zip: it is not held yet; its last fetch failed: its bytes hash to sha256:")
	_, metrics := env.get("/metrics")
	wantContains(t, metrics, "via_maris_pinned_unheld{upstream=\"gradle-files\"} 1\n")
	if entries, _ := os.ReadDir(env.held); len(entries) != 0 {
		t.Errorf("a file that failed its digest was kept: %v", entries)
	}

	os.WriteFile(filepath.Join(env.held, "0000stale"), []byte("old"), 0o644)
	env.maven.put("/distributions/gradle-9.3.1-bin.zip", string(env.dist), 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for h.unheld() != 0 || fileExists(filepath.Join(env.held, "0000stale")) {
		if time.Now().After(deadline) {
			t.Fatal("the file was not held, or the unpinned file not removed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	resp, body := fetchBody(t, env.mappedMaven(), "https://dist.test/distributions/gradle-9.3.1-bin.zip")
	if resp.StatusCode != http.StatusOK || body != string(env.dist) {
		t.Errorf("held: %d %q", resp.StatusCode, body)
	}

	env.maven.put("/distributions/gradle-9.3.1-bin.zip", "upstream gone", 0)
	again := newHeldFiles(env.g, h.up)
	again.fetchMissing(context.Background())
	if again.unheld() != 0 {
		t.Error("a held copy matching its pin was fetched again")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestMavenByNameValidation(t *testing.T) {
	base := func() *Config {
		c := &Config{Upstreams: []Upstream{
			{Name: "pypi", Ecosystem: "PyPI", URL: "https://pypi.org", Files: "https://files.pythonhosted.org"},
			mavenUpstream("central", "https://repo.maven.apache.org/maven2"),
			mavenUpstream("google", "https://dl.google.com/dl/android/maven2"),
			{Name: "gradle", Ecosystem: "files", Held: "/var/held", Pinned: []PinnedFile{{Name: "g.zip", URL: "https://services.gradle.org/distributions/g.zip"}}},
			{Name: "npm", Ecosystem: "npm", URL: "https://registry.npmjs.org"},
		}}
		return c
	}
	m := func() *MavenByName {
		return &MavenByName{Upstreams: []string{"central", "google"}, Files: "gradle", Listings: []string{"https://dl.google.com/android/repository"}, Cert: "c", Key: "k", CA: "a"}
	}
	if err := m().validate(base(), []string{"pypi.org"}); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
	if got := m().hosts(base()); strings.Join(got, ",") != "repo.maven.apache.org,dl.google.com,services.gradle.org" {
		t.Errorf("hosts %v", got)
	}
	for want, change := range map[string]func(*Config, *MavenByName){
		"is not a Maven upstream": func(c *Config, m *MavenByName) { m.Upstreams = []string{"npm"} },
		"is repeated":             func(c *Config, m *MavenByName) { m.Upstreams = []string{"central", "central"} },
		"overlap":                 func(c *Config, m *MavenByName) { m.Listings = []string{"https://dl.google.com/dl/android"} },
		"lies in a Maven repository": func(c *Config, m *MavenByName) {
			c.Upstreams[3].Pinned[0].URL = "https://repo.maven.apache.org/maven2/x.zip"
		},
		"names no files upstream that holds": func(c *Config, m *MavenByName) { c.Upstreams[3].Held = "" },
		"already a PyPI or npm name":         func(c *Config, m *MavenByName) { c.Upstreams[3].Pinned[0].URL = "https://pypi.org/g.zip" },
		"needs cert, key and ca":             func(c *Config, m *MavenByName) { m.CA = "" },
	} {
		c, mb := base(), m()
		change(c, mb)
		err := mb.validate(c, []string{"pypi.org", "files.pythonhosted.org"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error containing %q, got %v", want, err)
		}
	}
}
