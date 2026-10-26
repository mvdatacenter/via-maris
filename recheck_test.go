package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain stands in for OSV-Scanner when the re-check runs the test binary
// as its scanner: it reads every package-lock.json under the scanned root and
// lists fsevents 1.2.4 as malicious, as OSV's npm export does.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "scan" && os.Args[2] == "source" {
		os.Exit(fakeScanner(os.Args[3:]))
	}
	os.Exit(m.Run())
}

func fakeScanner(args []string) int {
	out, root := "", args[len(args)-1]
	for i, a := range args {
		if a == "--output-file" {
			out = args[i+1]
		}
	}
	type vuln struct {
		ID string `json:"id"`
	}
	type pkg struct {
		Package         map[string]string `json:"package"`
		Vulnerabilities []vuln            `json:"vulnerabilities,omitempty"`
	}
	type result struct {
		Source   map[string]string `json:"source"`
		Packages []pkg             `json:"packages"`
	}
	var results []result
	found := false
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Name() != "package-lock.json" {
			return err
		}
		b, _ := os.ReadFile(path)
		var lock struct {
			Packages map[string]struct{ Version string } `json:"packages"`
		}
		json.Unmarshal(b, &lock)
		res := result{Source: map[string]string{"path": path, "type": "lockfile"}}
		for k, p := range lock.Packages {
			name, ok := strings.CutPrefix(k, "node_modules/")
			if !ok {
				continue
			}
			e := pkg{Package: map[string]string{"name": name, "version": p.Version, "ecosystem": "npm"}}
			if name == "fsevents" && p.Version == "1.2.4" {
				e.Vulnerabilities = []vuln{{"MAL-2023-462"}, {"GHSA-8r6j-v8pm-fqw3"}}
				found = true
			}
			res.Packages = append(res.Packages, e)
		}
		results = append(results, res)
		return nil
	})
	if len(results) == 0 {
		return 128
	}
	b, _ := json.Marshal(map[string]any{"results": results})
	os.WriteFile(out, b, 0o644)
	if found {
		return 1
	}
	return 0
}

type tarEntry struct {
	name, body string
	kind       byte
}

func tarball(t *testing.T, entries ...tarEntry) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: e.kind}
		if e.kind == tar.TypeSymlink {
			h.Size, h.Linkname = 0, e.body
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.kind == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

const demoLock = `{"lockfileVersion":3,"packages":{"":{"name":"demo"},
 "node_modules/fsevents":{"version":"1.2.4"},"node_modules/left-pad":{"version":"1.3.0"}}}`

type fakeGitHub struct {
	t        *testing.T
	key      *rsa.PrivateKey
	mu       sync.Mutex
	repos    []map[string]any
	tarballs map[string][]byte
	fetched  []string
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{t: t, key: key, tarballs: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(gh.serve))
	t.Cleanup(srv.Close)
	t.Setenv("TEST_APP_ID", "12345")
	t.Setenv("TEST_INSTALLATION_ID", "678")
	t.Setenv("TEST_APP_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	return gh, srv
}

func (gh *fakeGitHub) repo(name string, archived bool, size int) {
	gh.repos = append(gh.repos, map[string]any{
		"name": name, "full_name": "example-org/" + name, "archived": archived, "size": size,
		"owner": map[string]string{"login": "example-org"},
	})
}

func (gh *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	gh.mu.Lock()
	defer gh.mu.Unlock()
	auth := r.Header.Get("Authorization")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/678/access_tokens":
		if err := gh.verifyJWT(strings.TrimPrefix(auth, "Bearer ")); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"permissions":{"contents":"read"}}` {
			http.Error(w, "asked for "+string(body), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"token":"ghs_test"}`))
	case auth != "Bearer ghs_test":
		http.Error(w, "bad credentials", http.StatusUnauthorized)
	case r.URL.Path == "/installation/repositories":
		json.NewEncoder(w).Encode(map[string]any{"repositories": gh.repos})
	case strings.HasSuffix(r.URL.Path, "/tarball"):
		full := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/tarball")
		gh.fetched = append(gh.fetched, full)
		b, ok := gh.tarballs[full]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func (gh *fakeGitHub) verifyJWT(jwt string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return io.ErrUnexpectedEOF
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&gh.key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct{ Iss, Iat, Exp int64 }
	if err := json.Unmarshal(claims, &c); err != nil {
		return err
	}
	if now := time.Now().Unix(); c.Iss != 12345 || c.Iat > now || c.Exp <= now || c.Exp-c.Iat > 600 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

type fakeAlertmanager struct {
	mu     sync.Mutex
	posts  [][]map[string]any
	status int
}

func newFakeAlertmanager(t *testing.T) (*fakeAlertmanager, *httptest.Server) {
	am := &fakeAlertmanager{status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		am.mu.Lock()
		defer am.mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		var alerts []map[string]any
		json.NewDecoder(r.Body).Decode(&alerts)
		am.posts = append(am.posts, alerts)
		w.WriteHeader(am.status)
	}))
	t.Cleanup(srv.Close)
	return am, srv
}

type recheckEnv struct {
	t     *testing.T
	gh    *fakeGitHub
	am    *fakeAlertmanager
	store *fakeStore
	cfg   *RecheckConfig
}

func newRecheckEnv(t *testing.T) *recheckEnv {
	t.Helper()
	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	env := &recheckEnv{t: t}
	var ghSrv, amSrv, storeSrv *httptest.Server
	env.gh, ghSrv = newFakeGitHub(t)
	env.am, amSrv = newFakeAlertmanager(t)
	env.store, storeSrv = newFakeStore(t)
	store := Store{Endpoint: storeSrv.URL, Region: "test", Bucket: "bucket", AccessKeyIDEnv: "TEST_KEY_ID", SecretAccessKeyEnv: "TEST_SECRET"}
	cfg := &RecheckConfig{}
	cfg.GitHub.API = ghSrv.URL
	cfg.GitHub.Org = "example-org"
	cfg.GitHub.AppIDEnv, cfg.GitHub.InstallationIDEnv, cfg.GitHub.PrivateKeyEnv = "TEST_APP_ID", "TEST_INSTALLATION_ID", "TEST_APP_KEY"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Scanner.Path = exe
	cfg.Scanner.WorkDir = t.TempDir()
	cfg.Alertmanager.URL = amSrv.URL
	cfg.Alertmanager.ResolveAfter = Duration{45 * time.Minute}
	cfg.InUse.Store = store
	cfg.InUse.Object = "in-use.json"
	cfg.Records.Store = store
	cfg.Records.Prefix = "records/"
	cfg.Records.Window = Duration{30 * day}
	if err := cfg.validate(); err != nil {
		t.Fatalf("test configuration: %v", err)
	}
	env.cfg = cfg
	return env
}

func (env *recheckEnv) run(now time.Time) (*recheckResult, error) {
	client := http.DefaultClient
	rc := &recheck{cfg: env.cfg, client: client, inUse: newObjectStore(env.cfg.InUse.Store, client), records: newObjectStore(env.cfg.Records.Store, client), start: now}
	return rc.run(context.Background())
}

func (env *recheckEnv) putRecords(at time.Time, recs ...record) string {
	var b bytes.Buffer
	for _, r := range recs {
		line, _ := json.Marshal(r)
		b.Write(append(line, '\n'))
	}
	key := "/bucket/records/" + at.UTC().Format(recordKeyTime) + "-via-maris-abc.ndjson"
	env.store.put(key, b.Bytes())
	return key
}

func served(eco, pkg, v string, at time.Time) record {
	return record{Time: at.UTC().Format(time.RFC3339Nano), Ecosystem: eco, Kind: "artifact", Package: pkg, Version: v, Served: true}
}

func (env *recheckEnv) inUse() *inUseFile {
	env.t.Helper()
	env.store.mu.Lock()
	b := env.store.objects["/bucket/in-use.json"]
	env.store.mu.Unlock()
	var f inUseFile
	if err := json.Unmarshal(b, &f); err != nil {
		env.t.Fatalf("in-use.json %q: %v", b, err)
	}
	return &f
}

func TestRecheckAlertsOnALockedMaliciousVersionAndWritesTheInUseSet(t *testing.T) {
	env := newRecheckEnv(t)
	env.gh.repo("demo", false, 10)
	env.gh.repo("old", true, 10)
	env.gh.repo("empty", false, 0)
	env.gh.repos = append(env.gh.repos, map[string]any{"name": "theirs", "full_name": "other/theirs", "owner": map[string]string{"login": "other"}})
	env.gh.tarballs["example-org/demo"] = tarball(t,
		tarEntry{"example-org-demo-abc123/web/package-lock.json", demoLock, tar.TypeReg},
		tarEntry{"example-org-demo-abc123/link", "/etc/passwd", tar.TypeSymlink},
		tarEntry{"example-org-demo-abc123/../../escape", "x", tar.TypeReg},
	)
	now := time.Now().UTC()
	env.putRecords(now.Add(-40*day), served("npm", "ancient", "1.0.0", now.Add(-40*day)))
	newest := now.Add(-time.Hour)
	env.putRecords(now.Add(-2*time.Hour),
		served("npm", "left-pad", "2.0.0", now.Add(-2*time.Hour)),
		served("PyPI", "Typing_Extensions", "4.12.2", now.Add(-2*time.Hour)),
		record{Time: now.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "refused", Version: "1.0.0"},
		record{Time: now.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "metadata", Package: "listing", Served: true},
	)
	env.putRecords(newest, served("Go", "golang.org/x/text", "v0.20.0", newest))

	res, err := env.run(now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(env.gh.fetched, " ") != "example-org/demo example-org/empty" {
		t.Errorf("fetched %v, want the org's two non-archived repositories", env.gh.fetched)
	}
	if _, err := os.Stat(filepath.Join(env.cfg.Scanner.WorkDir, "escape")); err == nil {
		t.Error("a tarball entry climbing out of the repository was written")
	}
	if _, err := os.Lstat(filepath.Join(env.cfg.Scanner.WorkDir, "repos", "demo", "link")); err == nil {
		t.Error("a symlink entry was written")
	}

	set := env.inUse()
	if !set.Generated.Equal(now) || !set.RecordsThrough.Equal(newest.Truncate(time.Nanosecond)) {
		t.Errorf("generated %s through %s, want %s through %s", set.Generated, set.RecordsThrough, now, newest)
	}
	want := map[string]map[string][]string{
		"npm":  {"fsevents": {"1.2.4"}, "left-pad": {"1.3.0", "2.0.0"}},
		"PyPI": {"typing-extensions": {"4.12.2"}},
		"Go":   {"golang.org/x/text": {"v0.20.0"}},
	}
	if got, _ := json.Marshal(set.Ecosystems); string(got) != mustJSON(want) {
		t.Errorf("in-use set\n got %s\nwant %s", got, mustJSON(want))
	}
	if res.lockfiles != 1 || res.locked != 2 || res.served != 3 {
		t.Errorf("result %+v", res)
	}

	g := &inUseSet{store: newObjectStore(env.cfg.InUse.Store, http.DefaultClient), object: "in-use.json"}
	if err := g.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := g.versions("PyPI", "typing_extensions"); len(got) != 1 || got[0] != "4.12.2" {
		t.Errorf("gateway reads typing_extensions as %v", got)
	}

	if len(env.am.posts) != 1 || len(env.am.posts[0]) != 1 {
		t.Fatalf("alerts posted: %v", env.am.posts)
	}
	a := env.am.posts[0][0]
	labels, _ := json.Marshal(a["labels"])
	if string(labels) != `{"advisory":"MAL-2023-462","alertname":"LockedVersionListedMalicious","ecosystem":"npm","lockfile":"web/package-lock.json","package":"fsevents","repository":"demo","severity":"critical","version":"1.2.4"}` {
		t.Errorf("labels %s", labels)
	}
	starts, _ := time.Parse(time.RFC3339Nano, a["startsAt"].(string))
	ends, _ := time.Parse(time.RFC3339Nano, a["endsAt"].(string))
	if time.Since(starts) > time.Minute || ends.Sub(starts) != 45*time.Minute {
		t.Errorf("startsAt %s endsAt %s, want now and 45m on", starts, ends)
	}
	wantContains(t, a["annotations"].(map[string]any)["summary"].(string), "example-org/demo web/package-lock.json locks fsevents@1.2.4, listed as malicious by MAL-2023-462")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRecheckReadsOnlyRecordsSinceItsLastRunAndDropsVersionsPastTheWindow(t *testing.T) {
	env := newRecheckEnv(t)
	now := time.Now().UTC()
	through := now.Add(-time.Hour)
	prev := inUseFile{
		Generated:      through,
		RecordsThrough: through,
		Served: map[string]map[string]map[string]time.Time{"npm": {
			"kept":    {"1.0.0": now.Add(-29 * day)},
			"expired": {"1.0.0": now.Add(-31 * day)},
		}},
	}
	b, _ := json.Marshal(prev)
	env.store.put("/bucket/in-use.json", b)
	before := env.putRecords(through.Add(-recordLookback-time.Minute), served("npm", "read-before", "1.0.0", through))
	late := env.putRecords(through.Add(-time.Minute), served("npm", "landed-late", "1.0.0", through))
	newer := env.putRecords(now.Add(-time.Minute), served("npm", "kept", "1.1.0", now.Add(-time.Minute)))

	if _, err := env.run(now); err != nil {
		t.Fatal(err)
	}
	if env.store.getCount(before) != 0 || env.store.getCount(late) != 1 || env.store.getCount(newer) != 1 {
		t.Errorf("GETs: before %d, inside the lookback %d, newer %d; want 0, 1, 1", env.store.getCount(before), env.store.getCount(late), env.store.getCount(newer))
	}
	set := env.inUse()
	want := `{"npm":{"kept":["1.0.0","1.1.0"],"landed-late":["1.0.0"]}}`
	if got, _ := json.Marshal(set.Ecosystems); string(got) != want {
		t.Errorf("in-use set %s, want %s", got, want)
	}
	if len(env.am.posts) != 0 {
		t.Errorf("alerts posted with nothing listed: %v", env.am.posts)
	}
}

func TestRecheckFailures(t *testing.T) {
	t.Run("a scanner that cannot run writes no set", func(t *testing.T) {
		env := newRecheckEnv(t)
		env.gh.repo("demo", false, 10)
		env.gh.tarballs["example-org/demo"] = tarball(t, tarEntry{"x/package-lock.json", demoLock, tar.TypeReg})
		env.cfg.Scanner.Path = "/nonexistent/osv-scanner"
		if _, err := env.run(time.Now()); err == nil || !strings.Contains(err.Error(), "osv-scanner") {
			t.Fatalf("err = %v", err)
		}
		if len(env.store.keys("/bucket/in-use.json")) != 0 {
			t.Error("an in-use set was written without a scan")
		}
	})
	t.Run("a repository whose tarball fails stops the run", func(t *testing.T) {
		env := newRecheckEnv(t)
		env.gh.repo("demo", false, 10)
		if _, err := env.run(time.Now()); err == nil || !strings.Contains(err.Error(), "example-org/demo: GET tarball: 404") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no lockfile anywhere still writes the served versions", func(t *testing.T) {
		env := newRecheckEnv(t)
		env.gh.repo("empty", false, 0)
		now := time.Now().UTC()
		env.putRecords(now.Add(-time.Minute), served("npm", "left-pad", "1.3.0", now.Add(-time.Minute)))
		if _, err := env.run(now); err != nil {
			t.Fatal(err)
		}
		if got, _ := json.Marshal(env.inUse().Ecosystems); string(got) != `{"npm":{"left-pad":["1.3.0"]}}` {
			t.Errorf("in-use set %s", got)
		}
	})
	t.Run("an Alertmanager that refuses fails the run after the set is written", func(t *testing.T) {
		env := newRecheckEnv(t)
		env.gh.repo("demo", false, 10)
		env.gh.tarballs["example-org/demo"] = tarball(t, tarEntry{"x/package-lock.json", demoLock, tar.TypeReg})
		env.am.status = http.StatusBadRequest
		if _, err := env.run(time.Now()); err == nil || !strings.Contains(err.Error(), "alertmanager: POST /api/v2/alerts: 400") {
			t.Fatalf("err = %v", err)
		}
		if len(env.store.keys("/bucket/in-use.json")) != 1 {
			t.Error("the in-use set was not written")
		}
	})
	t.Run("an unreadable previous set stops the run", func(t *testing.T) {
		env := newRecheckEnv(t)
		env.store.setFail(true)
		if _, err := env.run(time.Now()); err == nil || !strings.Contains(err.Error(), "GET bucket/in-use.json: 500") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestExampleRecheckConfigLoads(t *testing.T) {
	setExampleKeys(t)
	for _, env := range []string{"GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY"} {
		t.Setenv(env, "x")
	}
	cfg, err := loadRecheckConfig("recheck.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Records.Window.Duration != 30*day || cfg.Alertmanager.ResolveAfter.Duration != 45*time.Minute {
		t.Errorf("loaded %+v", cfg)
	}
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	if _, err := loadRecheckConfig("recheck.example.json"); err == nil || !strings.Contains(err.Error(), "privateKeyEnv") {
		t.Errorf("an unset key variable: %v", err)
	}
}
