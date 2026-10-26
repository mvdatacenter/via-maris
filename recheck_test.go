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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tarball(t *testing.T, files map[string]string, links ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "mvdatacenter-app-abc123/", Typeflag: tar.TypeDir, Mode: 0o755})
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "mvdatacenter-app-abc123/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	for i := 0; i+1 < len(links); i += 2 {
		tw.WriteHeader(&tar.Header{Name: "mvdatacenter-app-abc123/" + links[i], Typeflag: tar.TypeSymlink, Linkname: links[i+1]})
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type fakeGitHub struct {
	t        *testing.T
	key      *rsa.PublicKey
	repos    []map[string]any
	tarballs map[string][]byte
	asked    string
}

func newFakeGitHub(t *testing.T, key *rsa.PublicKey) (*fakeGitHub, *httptest.Server) {
	gh := &fakeGitHub{t: t, key: key, tarballs: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			if err := gh.verifyJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != "" {
				http.Error(w, err, http.StatusUnauthorized)
				return
			}
			b, _ := io.ReadAll(r.Body)
			gh.asked = string(b)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token":"installation-token"}`))
		case r.Header.Get("Authorization") != "token installation-token":
			http.Error(w, "bad credentials", http.StatusUnauthorized)
		case r.URL.Path == "/installation/repositories":
			json.NewEncoder(w).Encode(map[string]any{"total_count": len(gh.repos), "repositories": gh.repos})
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			b, ok := gh.tarballs[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return gh, srv
}

func (gh *fakeGitHub) verifyJWT(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "not a JWT"
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(gh.key, crypto.SHA256, sum[:], sig) != nil {
		return "bad signature"
	}
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	json.Unmarshal(claims, &c)
	if now := time.Now().Unix(); c.Iss != "1234" || c.Iat > now || c.Exp <= now || c.Exp-c.Iat > 600 {
		return "bad claims " + string(claims)
	}
	return ""
}

func repo(name string, archived bool) map[string]any {
	owner, _, _ := strings.Cut(name, "/")
	return map[string]any{"full_name": name, "default_branch": "main", "archived": archived, "owner": map[string]string{"login": owner}}
}

type fakeAlertmanager struct {
	mu     sync.Mutex
	alerts []map[string]any
	down   bool
}

func newFakeAlertmanager(t *testing.T) (*fakeAlertmanager, *httptest.Server) {
	am := &fakeAlertmanager{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		am.mu.Lock()
		defer am.mu.Unlock()
		if am.down || r.Method != http.MethodPost || r.URL.Path != "/api/v2/alerts" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var got []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		am.alerts = append(am.alerts, got...)
	}))
	t.Cleanup(srv.Close)
	return am, srv
}

type recheckEnv struct {
	t      *testing.T
	run    *recheckRun
	gh     *fakeGitHub
	am     *fakeAlertmanager
	osv    *osvExport
	store  *fakeStore
	locked []lockedPackage
	root   string
}

func newRecheckEnv(t *testing.T) *recheckEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	t.Setenv("APP_ID", "1234")
	t.Setenv("APP_INSTALLATION_ID", "77")
	t.Setenv("APP_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	env := &recheckEnv{t: t}
	var ghSrv, amSrv, osvSrv, storeSrv *httptest.Server
	env.gh, ghSrv = newFakeGitHub(t, &key.PublicKey)
	env.am, amSrv = newFakeAlertmanager(t)
	env.osv, osvSrv = newOSVExport(t)
	env.store, storeSrv = newFakeStore(t)
	store := Store{Endpoint: storeSrv.URL, Region: "test", Bucket: "bucket", AccessKeyIDEnv: "TEST_KEY_ID", SecretAccessKeyEnv: "TEST_SECRET"}

	cfg := &RecheckConfig{Ecosystems: []string{"npm", "PyPI"}, OSVScanner: "/osv-scanner", WorkDir: t.TempDir(), Alertmanager: amSrv.URL, AlertFor: Duration{45 * time.Minute}}
	cfg.Advisories.Source = osvSrv.URL
	cfg.GitHub.API = ghSrv.URL
	cfg.GitHub.Owner = "mvdatacenter"
	cfg.GitHub.AppIDEnv, cfg.GitHub.InstallationIDEnv, cfg.GitHub.PrivateKeyEnv = "APP_ID", "APP_INSTALLATION_ID", "APP_KEY"
	cfg.InUse.Store, cfg.InUse.Object = store, "in-use.json"
	cfg.Records.Store, cfg.Records.Prefix, cfg.Records.Overlap = store, "records/", Duration{10 * time.Minute}
	cfg.ServedWindow = Duration{30 * day}
	if err := cfg.validate(); err != nil {
		t.Fatalf("test configuration: %v", err)
	}
	env.run, err = newRecheckRun(cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	env.root = filepath.Join(cfg.WorkDir, "src")
	env.run.src.scan = func(ctx context.Context, root string) ([]lockedPackage, error) {
		var out []lockedPackage
		for _, p := range env.locked {
			if _, err := os.Stat(filepath.Join(root, p.Repository, p.Lockfile)); err == nil {
				out = append(out, p)
			}
		}
		return out, nil
	}
	env.osv.set(t, "npm", osvJSON("MAL-2023-462", "npm", "fsevents", nil, []map[string]string{ev("introduced", "1.0.0"), ev("fixed", "1.2.11")}))
	env.osv.set(t, "PyPI")
	return env
}

func (env *recheckEnv) inUse() inUseObject {
	env.t.Helper()
	env.store.mu.Lock()
	b := env.store.objects["/bucket/in-use.json"]
	env.store.mu.Unlock()
	var o inUseObject
	if err := json.Unmarshal(b, &o); err != nil {
		env.t.Fatalf("in-use.json %q: %v", b, err)
	}
	return o
}

func recordsObject(lines ...record) []byte {
	var b bytes.Buffer
	for _, r := range lines {
		l, _ := json.Marshal(r)
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func recordsKey(at time.Time) string {
	at = at.UTC()
	return "/bucket/records/" + at.Format("2006-01-02") + "/" + at.Format("150405.000000000") + "-via-maris-0.ndjson"
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
	if cfg.GitHub.Owner != "mvdatacenter" || cfg.ServedWindow.Duration != 30*day {
		t.Errorf("loaded %+v", cfg)
	}
}

func TestRecheckAlertsOnALockedMaliciousVersionAndWritesTheInUseSet(t *testing.T) {
	env := newRecheckEnv(t)
	env.gh.repos = []map[string]any{repo("mvdatacenter/app", false), repo("mvdatacenter/old", true), repo("someone-else/app", false), repo("mvdatacenter/empty", false)}
	env.gh.tarballs["/repos/mvdatacenter/app/tarball/main"] = tarball(t, map[string]string{"web/package-lock.json": "{}", "uv.lock": ""})
	env.gh.tarballs["/repos/mvdatacenter/old/tarball/main"] = tarball(t, map[string]string{"package-lock.json": "{}"})
	env.locked = []lockedPackage{
		{"mvdatacenter/app", "web/package-lock.json", "npm", "fsevents", "1.2.4"},
		{"mvdatacenter/app", "web/package-lock.json", "npm", "left-pad", "1.2.0"},
		{"mvdatacenter/app", "uv.lock", "PyPI", "Requests", "2.31.0"},
		{"mvdatacenter/app", "go.mod", "Go", "golang.org/x/text", "0.3.0"},
		{"mvdatacenter/old", "package-lock.json", "npm", "fsevents", "1.2.7"},
	}
	served := time.Now().Add(-2 * time.Hour)
	env.store.put(recordsKey(served), recordsObject(
		record{Time: served.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "is-number", Version: "6.0.0", Served: true},
		record{Time: served.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "evil", Version: "1.0.0", Served: false},
		record{Time: served.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "metadata", Package: "lodash", Version: "4.17.21", Served: true},
	))

	before := time.Now().UTC()
	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(env.gh.asked, `"contents":"read"`) || strings.Count(env.gh.asked, ":") != 2 {
		t.Errorf("the installation token asked for %s, want Contents read alone", env.gh.asked)
	}
	if len(env.am.alerts) != 1 {
		t.Fatalf("alerts %v, want one for the app repository's fsevents", env.am.alerts)
	}
	labels := env.am.alerts[0]["labels"].(map[string]any)
	for k, want := range map[string]string{"alertname": "LockedVersionListedMalicious", "severity": "critical", "repository": "mvdatacenter/app",
		"lockfile": "web/package-lock.json", "package": "fsevents", "version": "1.2.4", "advisory": "MAL-2023-462"} {
		if labels[k] != want {
			t.Errorf("label %s = %v, want %s", k, labels[k], want)
		}
	}

	o := env.inUse()
	if o.Generated.Before(before.Add(-time.Second)) || o.Generated.After(time.Now()) {
		t.Errorf("generated %s, want the time the run started", o.Generated)
	}
	want := map[string]map[string][]string{
		"npm":  {"fsevents": {"1.2.4"}, "left-pad": {"1.2.0"}, "is-number": {"6.0.0"}},
		"PyPI": {"requests": {"2.31.0"}},
	}
	got, _ := json.Marshal(o.Ecosystems)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Errorf("in-use ecosystems\n got %s\nwant %s", got, wantJSON)
	}

	set := &inUseSet{store: env.run.inUse, object: "in-use.json"}
	if err := set.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if vs := set.versions("PyPI", "requests"); len(vs) != 1 || vs[0] != "2.31.0" {
		t.Errorf("the gateway reads PyPI requests as %v", vs)
	}
}

func TestRecheckReadsOnlyRecordsPastWhatTheLastRunRead(t *testing.T) {
	env := newRecheckEnv(t)
	now := time.Now().UTC()
	through := now.Add(-time.Hour)
	prev, _ := json.Marshal(inUseObject{
		Generated:      through,
		RecordsThrough: through,
		Served: map[string]map[string]map[string]time.Time{
			"npm": {"kept": {"1.0.0": now.Add(-29 * day)}, "expired": {"1.0.0": now.Add(-31 * day)}},
		},
	})
	env.store.put("/bucket/in-use.json", prev)
	// Read before: an object older than the overlap is not read again, so
	// a broken one there does not fail the run.
	env.store.put(recordsKey(through.Add(-20*time.Minute)), []byte("not json\n"))
	inOverlap := through.Add(-5 * time.Minute)
	env.store.put(recordsKey(inOverlap), recordsObject(record{Time: inOverlap.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "late", Version: "2.0.0", Served: true}))
	after := now.Add(-10 * time.Minute)
	env.store.put(recordsKey(after), recordsObject(record{Time: after.Format(time.RFC3339Nano), Ecosystem: "PyPI", Kind: "artifact", Package: "Some_Pkg", Version: "1.0", Served: true}))

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	o := env.inUse()
	if !o.RecordsThrough.Equal(after) {
		t.Errorf("recordsThrough %s, want the newest object read, %s", o.RecordsThrough, after)
	}
	npm := o.Ecosystems["npm"]
	if npm["kept"] == nil || npm["late"] == nil || npm["expired"] != nil {
		t.Errorf("npm in use %v, want kept and late, and expired dropped past the window", npm)
	}
	if o.Ecosystems["PyPI"]["some-pkg"] == nil {
		t.Errorf("PyPI in use %v, want some-pkg under its normalized name", o.Ecosystems["PyPI"])
	}

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o := env.inUse(); !o.RecordsThrough.Equal(after) {
		t.Errorf("recordsThrough moved to %s with no new records, want %s", o.RecordsThrough, after)
	}
}

func TestRecheckRebuildsServedVersionsWhenThePreviousSetIsLost(t *testing.T) {
	env := newRecheckEnv(t)
	for _, age := range []time.Duration{40 * day, 20 * day, 3 * day, 2 * time.Hour} {
		at := time.Now().Add(-age)
		env.store.put(recordsKey(at), recordsObject(record{Time: at.Format(time.RFC3339Nano), Ecosystem: "npm", Kind: "artifact", Package: "p", Version: age.String(), Served: true}))
	}
	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := env.inUse().Ecosystems["npm"]["p"]
	if strings.Join(got, ",") != "2h0m0s,480h0m0s,72h0m0s" {
		t.Errorf("rebuilt served versions %v, want the three inside 30 days", got)
	}
}

func TestAFailedRecheckLeavesThePreviousSetInPlace(t *testing.T) {
	env := newRecheckEnv(t)
	env.gh.repos = []map[string]any{repo("mvdatacenter/app", false)}
	env.gh.tarballs["/repos/mvdatacenter/app/tarball/main"] = tarball(t, map[string]string{"package-lock.json": "{}"})
	env.locked = []lockedPackage{{"mvdatacenter/app", "package-lock.json", "npm", "fsevents", "1.2.4"}}
	env.store.put("/bucket/in-use.json", []byte(`{"generated":"2026-10-25T00:00:00Z"}`))
	env.am.down = true
	err := env.run.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "posting 1 alerts") {
		t.Fatalf("run with Alertmanager down: %v", err)
	}
	if o := env.inUse(); !o.Generated.Equal(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("a failed run rewrote the in-use set, generated %s", o.Generated)
	}
}

func TestARepositoryThatWillNotDownloadFailsTheRun(t *testing.T) {
	env := newRecheckEnv(t)
	unreadable := repo("mvdatacenter/app", false)
	unreadable["size"] = 120
	env.gh.repos = []map[string]any{unreadable}
	err := env.run.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mvdatacenter/app: tarball: 404") {
		t.Fatalf("run over a repository with commits that answers 404: %v", err)
	}
}

func TestTarballEntriesStayInsideTheCheckout(t *testing.T) {
	dest := t.TempDir()
	outside := filepath.Join(filepath.Dir(dest), "escaped")
	b := tarball(t, map[string]string{"../../escaped": "x", "a/package-lock.json": "{}"}, "link", "/etc")
	if err := extractTarball(bytes.NewReader(b), dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Errorf("an entry climbing out of the checkout was written at %s", outside)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Error("a symbolic link was written")
	}
	if _, err := os.Stat(filepath.Join(dest, "a", "package-lock.json")); err != nil {
		t.Error(err)
	}
}

func TestParseScanNamesTheRepositoryAndLockfile(t *testing.T) {
	out := `{"results":[{"source":{"path":"/src/mvdatacenter/app/web/package-lock.json","type":"lockfile"},
	"packages":[{"package":{"name":"fsevents","version":"1.2.4","ecosystem":"npm","purl":"pkg:npm/fsevents@1.2.4"}}]}]}`
	pkgs, err := parseScan([]byte(out), "/src")
	if err != nil {
		t.Fatal(err)
	}
	want := lockedPackage{"mvdatacenter/app", "web/package-lock.json", "npm", "fsevents", "1.2.4"}
	if len(pkgs) != 1 || pkgs[0] != want {
		t.Errorf("parsed %v, want %v", pkgs, want)
	}
	if _, err := parseScan([]byte(`{"results":[{"source":{"path":"/etc/package-lock.json"}}]}`), "/src"); err == nil {
		t.Error("a path outside the scanned root was accepted")
	}
}

func TestScanLockfilesWithOSVScanner(t *testing.T) {
	bin := os.Getenv("VIA_MARIS_OSV_SCANNER")
	if bin == "" {
		t.Skip("VIA_MARIS_OSV_SCANNER is not set")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "mvdatacenter", "app")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","dependencies":{"fsevents":"1.2.4"}},"node_modules/fsevents":{"version":"1.2.4"}}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "uv.lock"), []byte("version = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"), 0o644)
	pkgs, err := scanLockfiles(context.Background(), bin, root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got := map[lockedPackage]bool{}
	for _, p := range pkgs {
		got[p] = true
	}
	for _, want := range []lockedPackage{
		{"mvdatacenter/app", "package-lock.json", "npm", "fsevents", "1.2.4"},
		{"mvdatacenter/app", "uv.lock", "PyPI", "requests", "2.31.0"},
	} {
		if !got[want] {
			t.Errorf("scan %v, missing %v", pkgs, want)
		}
	}
}
