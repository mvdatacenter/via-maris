package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExampleDependabotClampConfigLoads(t *testing.T) {
	for _, env := range []string{"GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY"} {
		t.Setenv(env, "x")
	}
	cfg, err := loadDependabotClampConfig("dependabot-clamp.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "http://via-maris:8480" || cfg.Upstream != "npm" || cfg.GitHub.Owner != "mvdatacenter" || cfg.MaxWritesPerPass != 20 {
		t.Errorf("loaded %+v", cfg)
	}
}

func TestDependabotClampConfigRefusals(t *testing.T) {
	for _, env := range []string{"GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY"} {
		t.Setenv(env, "x")
	}
	writeClampVariant := func(t *testing.T, edit func(c map[string]any)) string {
		t.Helper()
		b, err := os.ReadFile("dependabot-clamp.example.json")
		if err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		edit(c)
		out, _ := json.Marshal(c)
		p := filepath.Join(t.TempDir(), "dependabot-clamp.json")
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		edit func(c map[string]any)
		want string
	}{
		{"unknown field", func(c map[string]any) { c["extra"] = 1 }, `unknown field "extra"`},
		{"gateway trailing slash", func(c map[string]any) { c["gateway"] = "http://via-maris:8480/" }, "gateway must be an http(s) URL"},
		{"reserved upstream", func(c map[string]any) { c["upstream"] = "verdicts" }, `upstream "verdicts"`},
		{"missing owner", func(c map[string]any) { c["github"].(map[string]any)["owner"] = "" }, "github needs an http(s) api URL"},
		{"unset app key env", func(c map[string]any) {
			c["github"].(map[string]any)["privateKeyEnv"] = "VIA_MARIS_TEST_UNSET_KEY"
		}, "must name environment variables that are set"},
		{"zero maxWritesPerPass", func(c map[string]any) { c["maxWritesPerPass"] = 0 }, "maxWritesPerPass must be positive"},
		{"negative maxWritesPerPass", func(c map[string]any) { c["maxWritesPerPass"] = -3 }, "maxWritesPerPass must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadDependabotClampConfig(writeClampVariant(t, tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want substring %q", err, tc.want)
			}
		})
	}
	setExampleKeys(t)
	_, err := loadConfig(writeVariant(t, func(c map[string]any) { upstreamAt(c, 0)["name"] = "verdicts" }))
	if err == nil || !strings.Contains(err.Error(), `upstream name "verdicts"`) {
		t.Errorf("gateway upstream verdicts: %v", err)
	}
}

func TestSatisfiesNPMRange(t *testing.T) {
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"8.1.4", "^8.1.4", true},
		{"8.1.6", "^8.1.4", true},
		{"8.1.3", "^8.1.4", false},
		{"9.0.0", "^8.1.4", false},
		{"0.2.5", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.9.0", "~1", true},
		{"2.0.0", "~1", false},
		{"1.5.0", ">= 1.2.0 < 2.0.0", true},
		{"2.0.0", ">= 1.2.0 < 2.0.0", false},
		{"2.0.0", "^1.0.0 || ^2.0.0", true},
		{"3.0.0", "^1.0.0 || ^2.0.0", false},
		{"2.3.9", "1.2 - 2.3", true},
		{"2.4.0", "1.2 - 2.3", false},
		{"1.4.2", "1.x", true},
		{"2.0.0", "1.x", false},
		{"1.2.3-beta.1", "^1.2.0", false},
		{"1.2.3-beta.2", "^1.2.3-beta.1", true},
		{"1.2.4-beta.1", "^1.2.3-beta.1", false},
		{"1.2.4", "^1.2.3-beta.1", true},
	}
	for _, c := range cases {
		if got := satisfiesNPMRange(c.ver, c.rng); got != c.want {
			t.Errorf("satisfiesNPMRange(%q, %q) = %v, want %v", c.ver, c.rng, got, c.want)
		}
	}
}

type richNPMVersion struct {
	age                  time.Duration
	dependencies         map[string]string
	optionalDependencies map[string]string
	tgz                  []byte
	shasum               string
	integrity            string
}

type richFakeNPM struct {
	srv      *httptest.Server
	packages map[string]map[string]*richNPMVersion
}

func makeNPMTarball(t *testing.T, name, version string, deps map[string]string) ([]byte, string, string) {
	t.Helper()
	pkgJSON, err := json.Marshal(map[string]any{
		"name":         name,
		"version":      version,
		"dependencies": deps,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     "package/package.json",
		Mode:     0o644,
		Size:     int64(len(pkgJSON)),
		ModTime:  time.Unix(1700000000, 0),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(pkgJSON); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	s1 := sha1.Sum(raw)
	s512 := sha512.Sum512(raw)
	return raw, hex.EncodeToString(s1[:]), "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
}

func newRichFakeNPM(t *testing.T) *richFakeNPM {
	t.Helper()
	f := &richFakeNPM{packages: map[string]map[string]*richNPMVersion{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/"))
		if err != nil {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if name, file, ok := strings.Cut(p, "/-/"); ok {
			vers, known := f.packages[name]
			if !known {
				http.NotFound(w, r)
				return
			}
			for v, meta := range vers {
				if path.Base(name)+"-"+v+".tgz" == file {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Write(meta.tgz)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		vers, ok := f.packages[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		versionsMap := map[string]any{}
		timeMap := map[string]any{}
		for v, meta := range vers {
			entry := map[string]any{
				"name":    p,
				"version": v,
				"dist": map[string]any{
					"tarball":   f.srv.URL + "/" + p + "/-/" + path.Base(p) + "-" + v + ".tgz",
					"shasum":    meta.shasum,
					"integrity": meta.integrity,
				},
			}
			if len(meta.dependencies) > 0 {
				entry["dependencies"] = meta.dependencies
			}
			if len(meta.optionalDependencies) > 0 {
				entry["optionalDependencies"] = meta.optionalDependencies
			}
			versionsMap[v] = entry
			if meta.age >= 0 {
				timeMap[v] = ago(meta.age)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"name":     p,
			"versions": versionsMap,
			"time":     timeMap,
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *richFakeNPM) add(t *testing.T, pkg, ver string, age time.Duration, deps map[string]string) *richNPMVersion {
	t.Helper()
	tgz, shasum, integ := makeNPMTarball(t, pkg, ver, deps)
	v := &richNPMVersion{
		age:          age,
		dependencies: deps,
		tgz:          tgz,
		shasum:       shasum,
		integrity:    integ,
	}
	if f.packages[pkg] == nil {
		f.packages[pkg] = map[string]*richNPMVersion{}
	}
	f.packages[pkg][ver] = v
	return v
}

func TestNPMVerdictsEndpoint(t *testing.T) {
	reg := newRichFakeNPM(t)
	reg.add(t, "@hapi/subtext", "8.1.4", 45*day, map[string]string{"@hapi/wreck": "^18.1.2"})
	reg.add(t, "@hapi/subtext", "8.1.5", 2*day, nil)
	reg.add(t, "@hapi/subtext", "8.1.6", 1*day, nil)
	reg.add(t, "@hapi/subtext", "8.1.7", 1*day, nil)
	reg.add(t, "@hapi/subtext", "8.0.0", 90*day, nil)

	up := Upstream{
		Name:       "npm",
		Ecosystem:  "npm",
		URL:        reg.srv.URL,
		Hold:       Duration{30 * day},
		Advisories: "malicious",
		Exceptions: []Exception{{
			Package:  "@hapi/subtext",
			Version:  "8.1.7",
			Reason:   "tested exception",
			Reviewed: "PR #1",
			Expires:  Date{time.Now().Add(48 * time.Hour)},
		}},
	}
	env := newTestEnv(t, up)

	status, body := env.get("/verdicts/npm/" + url.PathEscape("@hapi/subtext"))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("before advisories load: status %d (%s), want 503", status, body)
	}
	wantContains(t, body, "advisory data for npm has not loaded")

	resp, err := http.Post(env.srv.URL+"/verdicts/npm/lodash", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /verdicts: status %d, want 405", resp.StatusCode)
	}
	if st, _ := env.get("/verdicts/npm/@hapi"); st != http.StatusNotFound {
		t.Errorf("incomplete scope: status %d, want 404", st)
	}

	env.osv.set(t, "npm",
		osvJSON("MAL-2026-0001", "npm", "@hapi/subtext", []string{"8.0.0"}),
		osvJSON("GHSA-test-1234", "npm", "@hapi/subtext", nil, []map[string]string{ev("introduced", "8.1.0"), ev("fixed", "8.1.5")}),
	)
	env.loadAdvisories()
	env.setInUse(time.Now(), map[string]map[string][]string{"npm": {"@hapi/subtext": {"8.1.4"}}})

	status, body = env.get("/verdicts/npm/" + url.PathEscape("@hapi/subtext"))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var got npmVerdictsResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "@hapi/subtext" || got.Upstream != "npm" {
		t.Errorf("header %+v", got)
	}
	if v := got.Versions["8.1.4"]; !v.Served || v.Published == "" || v.Shasum == "" || !strings.HasPrefix(v.Integrity, "sha512-") || v.Dependencies["@hapi/wreck"] != "^18.1.2" {
		t.Errorf("8.1.4 verdict: %+v", v)
	}
	if v := got.Versions["8.1.6"]; v.Served || !strings.Contains(v.Reason, "release-age hold until ") {
		t.Errorf("8.1.6 verdict: %+v", v)
	}
	if v := got.Versions["8.0.0"]; v.Served || !strings.Contains(v.Reason, "MAL-2026-0001") {
		t.Errorf("8.0.0 verdict: %+v", v)
	}
	if v := got.Versions["8.1.5"]; !v.Served || !strings.Contains(v.Reason, "GHSA-test-1234") {
		t.Errorf("8.1.5 fix release verdict: %+v", v)
	}
	if v := got.Versions["8.1.7"]; !v.Served || !strings.Contains(v.Reason, "hold exception") {
		t.Errorf("8.1.7 exception verdict: %+v", v)
	}
}

type mockClampGitHub struct {
	mu               sync.Mutex
	key              *rsa.PublicKey
	askedPermissions string
	repos            []map[string]any
	prs              map[string][]pullRequest
	prFiles          map[string][]pullFile
	files            map[string]string
	commits          map[string]string
	trees            map[string]map[string]string
	blobs            map[string]string
	comments         map[string][]issueComment
	refUpdates       []mockRefUpdate
	rejectNextRef422 bool
	seq              int
}

type mockRefUpdate struct {
	Repo   string
	Ref    string
	SHA    string
	Force  bool
	Parent string
	Files  map[string]string
	Msg    string
}

func newMockClampGitHub(t *testing.T, key *rsa.PublicKey) (*mockClampGitHub, *httptest.Server) {
	t.Helper()
	m := &mockClampGitHub{
		key:      key,
		prs:      map[string][]pullRequest{},
		prFiles:  map[string][]pullFile{},
		files:    map[string]string{},
		commits:  map[string]string{},
		trees:    map[string]map[string]string{},
		blobs:    map[string]string{},
		comments: map[string][]issueComment{},
	}
	ghVerifier := &fakeGitHub{t: t, key: key}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens" {
			if err := ghVerifier.verifyJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != "" {
				http.Error(w, err, http.StatusUnauthorized)
				return
			}
			b, _ := io.ReadAll(r.Body)
			m.askedPermissions = string(b)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token":"clamp-token"}`))
			return
		}
		if r.Header.Get("Authorization") != "token clamp-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/installation/repositories" {
			json.NewEncoder(w).Encode(map[string]any{"total_count": len(m.repos), "repositories": m.repos})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/repos/") {
			http.NotFound(w, r)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/repos/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		repoName := parts[0] + "/" + parts[1]
		sub := parts[2]

		switch {
		case r.Method == http.MethodGet && sub == "pulls":
			json.NewEncoder(w).Encode(m.prs[repoName])
		case r.Method == http.MethodGet && strings.HasPrefix(sub, "pulls/") && strings.HasSuffix(sub, "/files"):
			num := strings.TrimSuffix(strings.TrimPrefix(sub, "pulls/"), "/files")
			json.NewEncoder(w).Encode(m.prFiles[repoName+"#"+num])
		case r.Method == http.MethodGet && strings.HasPrefix(sub, "contents/"):
			filePath, _ := url.PathUnescape(strings.TrimPrefix(sub, "contents/"))
			ref := r.URL.Query().Get("ref")
			content, ok := m.files[repoName+"@"+ref+":"+filePath]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(content))
		case r.Method == http.MethodGet && strings.HasPrefix(sub, "issues/") && strings.HasSuffix(sub, "/comments"):
			num := strings.TrimSuffix(strings.TrimPrefix(sub, "issues/"), "/comments")
			json.NewEncoder(w).Encode(m.comments[repoName+"#"+num])
		case r.Method == http.MethodPost && strings.HasPrefix(sub, "issues/") && strings.HasSuffix(sub, "/comments"):
			num := strings.TrimSuffix(strings.TrimPrefix(sub, "issues/"), "/comments")
			var req struct{ Body string }
			json.NewDecoder(r.Body).Decode(&req)
			m.seq++
			c := issueComment{ID: int64(100 + m.seq), Body: req.Body}
			m.comments[repoName+"#"+num] = append(m.comments[repoName+"#"+num], c)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(c)
		case r.Method == http.MethodPatch && strings.HasPrefix(sub, "issues/comments/"):
			idStr := strings.TrimPrefix(sub, "issues/comments/")
			var req struct{ Body string }
			json.NewDecoder(r.Body).Decode(&req)
			for key, cs := range m.comments {
				for i := range cs {
					if fmt.Sprintf("%d", cs[i].ID) == idStr {
						cs[i].Body = req.Body
						m.comments[key] = cs
						json.NewEncoder(w).Encode(cs[i])
						return
					}
				}
			}
			http.NotFound(w, r)
		case r.Method == http.MethodGet && strings.HasPrefix(sub, "git/commits/"):
			sha := strings.TrimPrefix(sub, "git/commits/")
			treeSHA := m.commits[sha]
			if treeSHA == "" {
				treeSHA = "tree-" + sha
			}
			json.NewEncoder(w).Encode(map[string]any{"sha": sha, "tree": map[string]string{"sha": treeSHA}})
		case r.Method == http.MethodPost && sub == "git/blobs":
			var req struct{ Content string }
			json.NewDecoder(r.Body).Decode(&req)
			m.seq++
			sha := fmt.Sprintf("blob-%d", m.seq)
			m.blobs[sha] = req.Content
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		case r.Method == http.MethodPost && sub == "git/trees":
			var req struct {
				BaseTree string `json:"base_tree"`
				Tree     []struct {
					Path string `json:"path"`
					SHA  string `json:"sha"`
				} `json:"tree"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			m.seq++
			sha := fmt.Sprintf("tree-%d", m.seq)
			files := map[string]string{}
			for _, e := range req.Tree {
				files[e.Path] = m.blobs[e.SHA]
			}
			m.trees[sha] = files
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		case r.Method == http.MethodPost && sub == "git/commits":
			var req struct {
				Message string   `json:"message"`
				Tree    string   `json:"tree"`
				Parents []string `json:"parents"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			m.seq++
			sha := fmt.Sprintf("commit-%d", m.seq)
			m.commits[sha] = req.Tree
			parent := ""
			if len(req.Parents) > 0 {
				parent = req.Parents[0]
			}
			for k, v := range m.files {
				if strings.HasPrefix(k, repoName+"@"+parent+":") {
					p := strings.TrimPrefix(k, repoName+"@"+parent+":")
					m.files[repoName+"@"+sha+":"+p] = v
				}
			}
			for p, content := range m.trees[req.Tree] {
				m.files[repoName+"@"+sha+":"+p] = content
			}
			m.refUpdates = append(m.refUpdates, mockRefUpdate{
				Repo:   repoName,
				SHA:    sha,
				Parent: parent,
				Files:  m.trees[req.Tree],
				Msg:    req.Message,
			})
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		case r.Method == http.MethodPatch && strings.HasPrefix(sub, "git/refs/heads/"):
			if m.rejectNextRef422 {
				m.rejectNextRef422 = false
				http.Error(w, "Update is not a fast forward", http.StatusUnprocessableEntity)
				return
			}
			ref, _ := url.PathUnescape(strings.TrimPrefix(sub, "git/refs/heads/"))
			var req struct {
				SHA   string `json:"sha"`
				Force bool   `json:"force"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			for i := range m.refUpdates {
				if m.refUpdates[i].SHA == req.SHA {
					m.refUpdates[i].Ref = ref
					m.refUpdates[i].Force = req.Force
				}
			}
			for i := range m.prs[repoName] {
				if m.prs[repoName][i].Head.Ref == ref {
					m.prs[repoName][i].Head.SHA = req.SHA
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"ref": "refs/heads/" + ref, "object": map[string]string{"sha": req.SHA}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return m, srv
}

func makePR(num int, author, headRepo, baseRepo, headRef, headSHA, baseSHA string) pullRequest {
	var pr pullRequest
	pr.Number = num
	pr.User.Login = author
	pr.Head.Ref = headRef
	pr.Head.SHA = headSHA
	pr.Head.Repo = &struct {
		FullName string `json:"full_name"`
	}{FullName: headRepo}
	pr.Base.Ref = "main"
	pr.Base.SHA = baseSHA
	pr.Base.Repo = &struct {
		FullName string `json:"full_name"`
	}{FullName: baseRepo}
	return pr
}

type clampTestEnv struct {
	t     *testing.T
	reg   *richFakeNPM
	gw    *testEnv
	gh    *mockClampGitHub
	run   *clampRun
	ghSrv *httptest.Server
	cfg   *DependabotClampConfig
}

func newClampTestEnv(t *testing.T, maxWrites int) *clampTestEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAMP_APP_ID", "1234")
	t.Setenv("CLAMP_INSTALLATION_ID", "77")
	t.Setenv("CLAMP_APP_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))

	reg := newRichFakeNPM(t)
	gw := newTestEnv(t, Upstream{Name: "npm", Ecosystem: "npm", URL: reg.srv.URL, Hold: Duration{30 * day}, Advisories: "malicious"})
	gw.loadAdvisories()
	gh, ghSrv := newMockClampGitHub(t, &key.PublicKey)

	cfg := &DependabotClampConfig{
		Gateway:          gw.srv.URL,
		Upstream:         "npm",
		MaxWritesPerPass: maxWrites,
	}
	cfg.GitHub.API = ghSrv.URL
	cfg.GitHub.Owner = "mvdatacenter"
	cfg.GitHub.AppIDEnv = "CLAMP_APP_ID"
	cfg.GitHub.InstallationIDEnv = "CLAMP_INSTALLATION_ID"
	cfg.GitHub.PrivateKeyEnv = "CLAMP_APP_KEY"
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	run, err := newClampRun(cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	return &clampTestEnv{t: t, reg: reg, gw: gw, gh: gh, run: run, ghSrv: ghSrv, cfg: cfg}
}

func fetchYarnLockTarballs(t *testing.T, gw *testEnv, lockText string) map[string]int {
	t.Helper()
	_, entries, err := parseYarnLock(lockText)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]int{}
	for _, e := range entries {
		pkg, _, _, _ := parseNPMSelector(e.selectors[0])
		u, err := url.Parse(e.resolved)
		if err != nil {
			t.Fatalf("bad resolved URL %q: %v", e.resolved, err)
		}
		tbFile := path.Base(u.Path)
		status, body := gw.get("/npm/" + pkg + "/-/" + tbFile)
		statuses[pkg+"@"+e.version] = status
		if status == http.StatusOK {
			s512 := sha512.Sum512([]byte(body))
			wantInteg := "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
			if e.integrity != "" && e.integrity != wantInteg {
				t.Errorf("%s@%s integrity mismatch: lock=%s actual=%s", pkg, e.version, e.integrity, wantInteg)
			}
		}
	}
	return statuses
}

func TestClampDependabotYarnLockEndToEnd(t *testing.T) {
	env := newClampTestEnv(t, 20)

	hapiOld := env.reg.add(t, "@hapi/hapi", "21.4.10", 60*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	hapiNew := env.reg.add(t, "@hapi/hapi", "21.4.11", 35*day, map[string]string{"@hapi/subtext": "^8.1.4", "@hapi/wreck": "^18.1.2"})
	subOld := env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)
	subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, map[string]string{"brand-new-dep": "^1.0.0"})
	orphan := env.reg.add(t, "brand-new-dep", "1.0.0", 40*day, nil)
	env.reg.add(t, "@hapi/wreck", "18.1.2", 45*day, nil)
	wreckHeld := env.reg.add(t, "@hapi/wreck", "18.1.3", 2*day, nil)

	pkgJSON := `{"name":"proxy","version":"1.0.0","dependencies":{"@hapi/hapi":"^21.4.11"}}` + "\n"
	baseLock := fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.4.10":
  version "21.4.10"
  resolved "https://registry.yarnpkg.com/@hapi/hapi/-/hapi-21.4.10.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.4"

"@hapi/subtext@^8.1.4":
  version "8.1.4"
  resolved "https://registry.yarnpkg.com/@hapi/subtext/-/subtext-8.1.4.tgz#%s"
  integrity %s
`, hapiOld.shasum, hapiOld.integrity, subOld.shasum, subOld.integrity)

	headLock := fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.4.11":
  version "21.4.11"
  resolved "https://registry.yarnpkg.com/@hapi/hapi/-/hapi-21.4.11.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.4"
    "@hapi/wreck" "^18.1.2"

"@hapi/subtext@^8.1.4":
  version "8.1.6"
  resolved "https://registry.yarnpkg.com/@hapi/subtext/-/subtext-8.1.6.tgz#%s"
  integrity %s
  dependencies:
    brand-new-dep "^1.0.0"

"@hapi/wreck@^18.1.2":
  version "18.1.3"
  resolved "https://registry.yarnpkg.com/@hapi/wreck/-/wreck-18.1.3.tgz#%s"
  integrity %s

brand-new-dep@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/brand-new-dep/-/brand-new-dep-1.0.0.tgz#%s"
  integrity %s
`, hapiNew.shasum, hapiNew.integrity, subHeld.shasum, subHeld.integrity, wreckHeld.shasum, wreckHeld.integrity, orphan.shasum, orphan.integrity)

	before := fetchYarnLockTarballs(t, env.gw, headLock)
	if before["@hapi/subtext@8.1.6"] != http.StatusForbidden || before["@hapi/wreck@18.1.3"] != http.StatusForbidden {
		t.Fatalf("unclamped tarballs %v, want 403 on held transitives", before)
	}

	env.gh.repos = []map[string]any{repo("mvdatacenter/app", false)}
	env.gh.prs["mvdatacenter/app"] = []pullRequest{
		makePR(42, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/npm_and_yarn/services/proxy/hapi-21.4.11", "head-sha-1", "base-sha-1"),
	}
	env.gh.prFiles["mvdatacenter/app#42"] = []pullFile{
		{Filename: "services/proxy/package.json", Status: "modified"},
		{Filename: "services/proxy/yarn.lock", Status: "modified"},
	}
	env.gh.files["mvdatacenter/app@head-sha-1:services/proxy/package.json"] = pkgJSON
	env.gh.files["mvdatacenter/app@head-sha-1:services/proxy/yarn.lock"] = headLock
	env.gh.files["mvdatacenter/app@base-sha-1:services/proxy/yarn.lock"] = baseLock

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}

	wantContains(t, env.gh.askedPermissions, `"contents":"write"`, `"pull_requests":"write"`)
	if len(env.gh.refUpdates) != 1 {
		t.Fatalf("refUpdates = %d, want 1", len(env.gh.refUpdates))
	}
	upd := env.gh.refUpdates[0]
	if upd.Force {
		t.Error("ref update used force=true, want force=false")
	}
	if upd.Parent != "head-sha-1" {
		t.Errorf("commit parent = %q, want head-sha-1", upd.Parent)
	}
	if len(upd.Files) != 1 {
		t.Fatalf("committed files = %v, want only yarn.lock (package.json untouched)", upd.Files)
	}
	clampedLock := upd.Files["services/proxy/yarn.lock"]
	if clampedLock == "" {
		t.Fatal("clamped yarn.lock missing from commit")
	}
	if strings.Contains(clampedLock, "brand-new-dep") {
		t.Errorf("orphan brand-new-dep was not pruned:\n%s", clampedLock)
	}
	if !strings.Contains(clampedLock, "https://registry.yarnpkg.com/@hapi/wreck/-/wreck-18.1.2.tgz") {
		t.Errorf("public registry host not preserved for fallback version:\n%s", clampedLock)
	}

	after := fetchYarnLockTarballs(t, env.gw, clampedLock)
	for _, want := range []string{"@hapi/hapi@21.4.11", "@hapi/subtext@8.1.4", "@hapi/wreck@18.1.2"} {
		if after[want] != http.StatusOK {
			t.Errorf("clamped tarball %s status = %d, want 200 (all: %v)", want, after[want], after)
		}
	}
	if len(after) != 3 {
		t.Errorf("clamped lockfile has %d entries %v, want 3", len(after), after)
	}

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(env.gh.refUpdates) != 1 || len(env.gh.comments["mvdatacenter/app#42"]) != 0 {
		t.Errorf("second pass was not idempotent: refUpdates=%d comments=%d", len(env.gh.refUpdates), len(env.gh.comments["mvdatacenter/app#42"]))
	}
}

func TestClampDependabotPackageLockV3AndV2EndToEnd(t *testing.T) {
	for _, lockfileVersion := range []int{3, 2} {
		t.Run(fmt.Sprintf("v%d", lockfileVersion), func(t *testing.T) {
			env := newClampTestEnv(t, 20)
			hapiOld := env.reg.add(t, "@hapi/hapi", "21.4.10", 60*day, map[string]string{"@hapi/subtext": "^8.1.4"})
			hapiNew := env.reg.add(t, "@hapi/hapi", "21.4.11", 35*day, map[string]string{"@hapi/subtext": "^8.1.4"})
			subOld := env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)
			subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, map[string]string{"orphan-pkg": "^1.0.0"})
			orphan := env.reg.add(t, "orphan-pkg", "1.0.0", 40*day, nil)

			pkgJSON := `{"name":"app","version":"1.0.0","dependencies":{"@hapi/hapi":"^21.4.11"}}` + "\n"
			baseObj := map[string]any{
				"name":            "app",
				"version":         "1.0.0",
				"lockfileVersion": lockfileVersion,
				"packages": map[string]any{
					"": map[string]any{"name": "app", "version": "1.0.0", "dependencies": map[string]string{"@hapi/hapi": "^21.4.10"}},
					"node_modules/@hapi/hapi": map[string]any{
						"version": "21.4.10", "resolved": "https://registry.npmjs.org/@hapi/hapi/-/hapi-21.4.10.tgz", "integrity": hapiOld.integrity,
						"dependencies": map[string]string{"@hapi/subtext": "^8.1.4"},
					},
					"node_modules/@hapi/subtext": map[string]any{
						"version": "8.1.4", "resolved": "https://registry.npmjs.org/@hapi/subtext/-/subtext-8.1.4.tgz", "integrity": subOld.integrity,
					},
				},
			}
			headObj := map[string]any{
				"name":            "app",
				"version":         "1.0.0",
				"lockfileVersion": lockfileVersion,
				"packages": map[string]any{
					"": map[string]any{"name": "app", "version": "1.0.0", "dependencies": map[string]string{"@hapi/hapi": "^21.4.11"}},
					"node_modules/@hapi/hapi": map[string]any{
						"version": "21.4.11", "resolved": "https://registry.npmjs.org/@hapi/hapi/-/hapi-21.4.11.tgz", "integrity": hapiNew.integrity,
						"dependencies": map[string]string{"@hapi/subtext": "^8.1.4"},
					},
					"node_modules/@hapi/subtext": map[string]any{
						"version": "8.1.6", "resolved": "https://registry.npmjs.org/@hapi/subtext/-/subtext-8.1.6.tgz", "integrity": subHeld.integrity,
						"dependencies": map[string]string{"orphan-pkg": "^1.0.0"},
					},
					"node_modules/orphan-pkg": map[string]any{
						"version": "1.0.0", "resolved": "https://registry.npmjs.org/orphan-pkg/-/orphan-pkg-1.0.0.tgz", "integrity": orphan.integrity,
					},
				},
			}
			if lockfileVersion == 2 {
				headObj["dependencies"] = map[string]any{
					"@hapi/hapi":    map[string]any{"version": "21.4.11", "resolved": "https://registry.npmjs.org/@hapi/hapi/-/hapi-21.4.11.tgz", "integrity": hapiNew.integrity},
					"@hapi/subtext": map[string]any{"version": "8.1.6", "resolved": "https://registry.npmjs.org/@hapi/subtext/-/subtext-8.1.6.tgz", "integrity": subHeld.integrity},
					"orphan-pkg":    map[string]any{"version": "1.0.0", "resolved": "https://registry.npmjs.org/orphan-pkg/-/orphan-pkg-1.0.0.tgz", "integrity": orphan.integrity},
				}
			}
			baseLock, _ := marshalJSONNoEscape(baseObj)
			headLock, _ := marshalJSONNoEscape(headObj)

			if st, _ := env.gw.get("/npm/@hapi/subtext/-/subtext-8.1.6.tgz"); st != http.StatusForbidden {
				t.Fatalf("unclamped subtext@8.1.6 status = %d, want 403", st)
			}

			env.gh.repos = []map[string]any{repo("mvdatacenter/app", false)}
			env.gh.prs["mvdatacenter/app"] = []pullRequest{
				makePR(12, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/npm_and_yarn/hapi-21.4.11", "head-1", "base-1"),
			}
			env.gh.prFiles["mvdatacenter/app#12"] = []pullFile{
				{Filename: "package.json", Status: "modified"},
				{Filename: "package-lock.json", Status: "modified"},
			}
			env.gh.files["mvdatacenter/app@head-1:package.json"] = pkgJSON
			env.gh.files["mvdatacenter/app@head-1:package-lock.json"] = headLock
			env.gh.files["mvdatacenter/app@base-1:package-lock.json"] = baseLock

			if err := env.run.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(env.gh.refUpdates) != 1 || env.gh.refUpdates[0].Force {
				t.Fatalf("refUpdates = %+v", env.gh.refUpdates)
			}
			clampedText := env.gh.refUpdates[0].Files["package-lock.json"]
			var clamped map[string]any
			if err := json.Unmarshal([]byte(clampedText), &clamped); err != nil {
				t.Fatal(err)
			}
			pkgs := clamped["packages"].(map[string]any)
			if _, exists := pkgs["node_modules/orphan-pkg"]; exists {
				t.Error("orphan-pkg was not pruned from packages")
			}
			subMeta := pkgs["node_modules/@hapi/subtext"].(map[string]any)
			if subMeta["version"] != "8.1.4" || subMeta["resolved"] != "https://registry.npmjs.org/@hapi/subtext/-/subtext-8.1.4.tgz" {
				t.Errorf("clamped subtext = %+v", subMeta)
			}
			if lockfileVersion == 2 {
				legacy := clamped["dependencies"].(map[string]any)
				if _, exists := legacy["orphan-pkg"]; exists {
					t.Error("orphan-pkg was not pruned from v2 legacy dependencies")
				}
				if legacy["@hapi/subtext"].(map[string]any)["version"] != "8.1.4" {
					t.Errorf("v2 legacy subtext = %+v", legacy["@hapi/subtext"])
				}
			}
			for p, raw := range pkgs {
				if p == "" {
					continue
				}
				m := raw.(map[string]any)
				_, realName := pkgNameForLockPath(p, m)
				u, _ := url.Parse(m["resolved"].(string))
				if st, _ := env.gw.get("/npm/" + realName + "/-/" + path.Base(u.Path)); st != http.StatusOK {
					t.Errorf("clamped tarball %s@%s status = %d, want 200", realName, m["version"], st)
				}
			}
			if err := env.run.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(env.gh.refUpdates) != 1 {
				t.Errorf("second pass wrote again: %d", len(env.gh.refUpdates))
			}
		})
	}
}

func TestClampDependabotFrozenInstallWithNPMCI(t *testing.T) {
	npmBin, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is not installed on PATH")
	}
	env := newClampTestEnv(t, 20)
	hapiOld := env.reg.add(t, "@hapi/hapi", "21.4.10", 60*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	hapiNew := env.reg.add(t, "@hapi/hapi", "21.4.11", 35*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	subOld := env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)
	subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, nil)

	regBase := env.gw.srv.URL + "/npm"
	pkgJSON := `{"name":"frozen-check","version":"1.0.0","dependencies":{"@hapi/hapi":"^21.4.11"}}` + "\n"
	baseLock, _ := marshalJSONNoEscape(map[string]any{
		"name": "frozen-check", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "frozen-check", "version": "1.0.0", "dependencies": map[string]string{"@hapi/hapi": "^21.4.10"}},
			"node_modules/@hapi/hapi": map[string]any{
				"version": "21.4.10", "resolved": regBase + "/@hapi/hapi/-/hapi-21.4.10.tgz", "integrity": hapiOld.integrity,
				"dependencies": map[string]string{"@hapi/subtext": "^8.1.4"},
			},
			"node_modules/@hapi/subtext": map[string]any{
				"version": "8.1.4", "resolved": regBase + "/@hapi/subtext/-/subtext-8.1.4.tgz", "integrity": subOld.integrity,
			},
		},
	})
	headLock, _ := marshalJSONNoEscape(map[string]any{
		"name": "frozen-check", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "frozen-check", "version": "1.0.0", "dependencies": map[string]string{"@hapi/hapi": "^21.4.11"}},
			"node_modules/@hapi/hapi": map[string]any{
				"version": "21.4.11", "resolved": regBase + "/@hapi/hapi/-/hapi-21.4.11.tgz", "integrity": hapiNew.integrity,
				"dependencies": map[string]string{"@hapi/subtext": "^8.1.4"},
			},
			"node_modules/@hapi/subtext": map[string]any{
				"version": "8.1.6", "resolved": regBase + "/@hapi/subtext/-/subtext-8.1.6.tgz", "integrity": subHeld.integrity,
			},
		},
	})

	runNPMCI := func(lockText string) ([]byte, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockText), 0o600); err != nil {
			t.Fatal(err)
		}
		cacheDir := filepath.Join(dir, "cache")
		cmd := exec.Command(npmBin, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--offline=false", "--prefer-online")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"npm_config_registry="+regBase+"/",
			"npm_config_cache="+cacheDir,
			"npm_config_proxy=",
			"npm_config_https_proxy=",
			"HTTP_PROXY=",
			"HTTPS_PROXY=",
			"http_proxy=",
			"https_proxy=",
		)
		return cmd.CombinedOutput()
	}

	outBefore, errBefore := runNPMCI(headLock)
	if errBefore == nil {
		t.Fatalf("expected unclamped npm ci to fail with 403, got success:\n%s", outBefore)
	}
	wantContains(t, string(outBefore), "403")

	clampedLock, changed, clamped, blocking, err := clampPackageLock(context.Background(), env.run.verdicts, pkgJSON, baseLock, headLock)
	if err != nil || !changed || len(blocking) > 0 || len(clamped) != 1 {
		t.Fatalf("clampPackageLock: changed=%v clamped=%v blocking=%v err=%v", changed, clamped, blocking, err)
	}
	outAfter, errAfter := runNPMCI(clampedLock)
	if errAfter != nil {
		t.Fatalf("clamped npm ci failed: %v\n%s", errAfter, outAfter)
	}
}

func TestClampDependabotFrozenInstallWithYarn(t *testing.T) {
	yarnBin := os.Getenv("VIA_MARIS_YARN_BIN")
	if yarnBin == "" {
		var err error
		yarnBin, err = exec.LookPath("yarn")
		if err != nil {
			t.Skip("yarn is not installed on PATH (set VIA_MARIS_YARN_BIN to run)")
		}
	}
	env := newClampTestEnv(t, 20)
	hapiOld := env.reg.add(t, "@hapi/hapi", "21.4.10", 60*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	hapiNew := env.reg.add(t, "@hapi/hapi", "21.4.11", 35*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	subOld := env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)
	subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, nil)

	regBase := env.gw.srv.URL + "/npm"
	pkgJSON := `{"name":"frozen-yarn","version":"1.0.0","dependencies":{"@hapi/hapi":"^21.4.11"}}` + "\n"
	baseLock := fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.4.10":
  version "21.4.10"
  resolved "%s/@hapi/hapi/-/hapi-21.4.10.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.4"

"@hapi/subtext@^8.1.4":
  version "8.1.4"
  resolved "%s/@hapi/subtext/-/subtext-8.1.4.tgz#%s"
  integrity %s
`, regBase, hapiOld.shasum, hapiOld.integrity, regBase, subOld.shasum, subOld.integrity)
	headLock := fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.4.11":
  version "21.4.11"
  resolved "%s/@hapi/hapi/-/hapi-21.4.11.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.4"

"@hapi/subtext@^8.1.4":
  version "8.1.6"
  resolved "%s/@hapi/subtext/-/subtext-8.1.6.tgz#%s"
  integrity %s
`, regBase, hapiNew.shasum, hapiNew.integrity, regBase, subHeld.shasum, subHeld.integrity)

	runYarn := func(lockText string) ([]byte, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(lockText), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(yarnBin, "install", "--frozen-lockfile", "--ignore-scripts", "--ignore-engines", "--cache-folder", filepath.Join(dir, "cache"))
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY=",
			"HTTPS_PROXY=",
			"http_proxy=",
			"https_proxy=",
		)
		return cmd.CombinedOutput()
	}

	outBefore, errBefore := runYarn(headLock)
	if errBefore == nil {
		t.Fatalf("expected unclamped yarn install --frozen-lockfile to fail with 403, got success:\n%s", outBefore)
	}
	wantContains(t, string(outBefore), "403")

	clampedLock, changed, clamped, blocking, err := clampYarnLock(context.Background(), env.run.verdicts, pkgJSON, baseLock, headLock)
	if err != nil || !changed || len(blocking) > 0 || len(clamped) != 1 {
		t.Fatalf("clampYarnLock: changed=%v clamped=%v blocking=%v err=%v", changed, clamped, blocking, err)
	}
	outAfter, errAfter := runYarn(clampedLock)
	if errAfter != nil {
		t.Fatalf("clamped yarn install --frozen-lockfile failed: %v\n%s", errAfter, outAfter)
	}
}

func TestClampDependabotUnclampableAndDirectDepComments(t *testing.T) {
	env := newClampTestEnv(t, 20)
	hapiStrict := env.reg.add(t, "@hapi/hapi", "21.5.0", 35*day, map[string]string{"@hapi/subtext": "^8.1.6"})
	hapiHeld := env.reg.add(t, "@hapi/hapi", "21.5.1", 1*day, nil)
	subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, nil)
	env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)

	env.gh.repos = []map[string]any{repo("mvdatacenter/app", false)}
	env.gh.prs["mvdatacenter/app"] = []pullRequest{
		makePR(1, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/npm_and_yarn/hapi-21.5.0", "sha-unclamp-1", "base-1"),
		makePR(2, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/npm_and_yarn/hapi-21.5.1", "sha-direct-1", "base-1"),
	}
	env.gh.prFiles["mvdatacenter/app#1"] = []pullFile{
		{Filename: "package.json", Status: "modified"},
		{Filename: "yarn.lock", Status: "modified"},
	}
	env.gh.prFiles["mvdatacenter/app#2"] = []pullFile{
		{Filename: "package.json", Status: "modified"},
		{Filename: "yarn.lock", Status: "modified"},
	}
	env.gh.files["mvdatacenter/app@sha-unclamp-1:package.json"] = `{"dependencies":{"@hapi/hapi":"^21.5.0"}}`
	env.gh.files["mvdatacenter/app@sha-unclamp-1:yarn.lock"] = fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.5.0":
  version "21.5.0"
  resolved "https://registry.yarnpkg.com/@hapi/hapi/-/hapi-21.5.0.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.6"

"@hapi/subtext@^8.1.6":
  version "8.1.6"
  resolved "https://registry.yarnpkg.com/@hapi/subtext/-/subtext-8.1.6.tgz#%s"
  integrity %s
`, hapiStrict.shasum, hapiStrict.integrity, subHeld.shasum, subHeld.integrity)

	env.gh.files["mvdatacenter/app@sha-direct-1:package.json"] = `{"dependencies":{"@hapi/hapi":"^21.5.1"}}`
	env.gh.files["mvdatacenter/app@sha-direct-1:yarn.lock"] = fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.5.1":
  version "21.5.1"
  resolved "https://registry.yarnpkg.com/@hapi/hapi/-/hapi-21.5.1.tgz#%s"
  integrity %s
`, hapiHeld.shasum, hapiHeld.integrity)

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(env.gh.refUpdates) != 0 {
		t.Fatalf("expected 0 commits for unclampable/direct-held PRs, got %d", len(env.gh.refUpdates))
	}
	c1 := env.gh.comments["mvdatacenter/app#1"]
	if len(c1) != 1 {
		t.Fatalf("PR #1 comments = %d, want 1", len(c1))
	}
	wantContains(t, c1[0].Body, "<!-- via-maris-clamp: head=sha-unclamp-1 -->", "@hapi/subtext@8.1.6", "release-age hold until ")

	c2 := env.gh.comments["mvdatacenter/app#2"]
	if len(c2) != 1 {
		t.Fatalf("PR #2 comments = %d, want 1", len(c2))
	}
	wantContains(t, c2[0].Body, "<!-- via-maris-clamp: head=sha-direct-1 -->", "direct dependency @hapi/hapi@21.5.1", "release-age hold until ")

	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(env.gh.comments["mvdatacenter/app#1"]) != 1 || len(env.gh.comments["mvdatacenter/app#2"]) != 1 {
		t.Fatalf("duplicate comments created on second pass")
	}

	env.gh.prs["mvdatacenter/app"][0].Head.SHA = "sha-unclamp-2"
	env.gh.files["mvdatacenter/app@sha-unclamp-2:package.json"] = env.gh.files["mvdatacenter/app@sha-unclamp-1:package.json"]
	env.gh.files["mvdatacenter/app@sha-unclamp-2:yarn.lock"] = env.gh.files["mvdatacenter/app@sha-unclamp-1:yarn.lock"]
	if err := env.run.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c1 = env.gh.comments["mvdatacenter/app#1"]
	if len(c1) != 1 {
		t.Fatalf("PR #1 after rebase has %d comments, want 1 updated in place", len(c1))
	}
	wantContains(t, c1[0].Body, "<!-- via-maris-clamp: head=sha-unclamp-2 -->")
}

func TestClampDependabotFilteringRefMovedCapAndFailClosed(t *testing.T) {
	env := newClampTestEnv(t, 1)
	hapiNew := env.reg.add(t, "@hapi/hapi", "21.4.11", 35*day, map[string]string{"@hapi/subtext": "^8.1.4"})
	env.reg.add(t, "@hapi/subtext", "8.1.4", 50*day, nil)
	subHeld := env.reg.add(t, "@hapi/subtext", "8.1.6", 1*day, nil)

	pkgJSON := `{"dependencies":{"@hapi/hapi":"^21.4.11"}}`
	heldLock := fmt.Sprintf(`# yarn lockfile v1

"@hapi/hapi@^21.4.11":
  version "21.4.11"
  resolved "https://registry.yarnpkg.com/@hapi/hapi/-/hapi-21.4.11.tgz#%s"
  integrity %s
  dependencies:
    "@hapi/subtext" "^8.1.4"

"@hapi/subtext@^8.1.4":
  version "8.1.6"
  resolved "https://registry.yarnpkg.com/@hapi/subtext/-/subtext-8.1.6.tgz#%s"
  integrity %s
`, hapiNew.shasum, hapiNew.integrity, subHeld.shasum, subHeld.integrity)

	env.gh.repos = []map[string]any{
		repo("mvdatacenter/app", false),
		repo("mvdatacenter/archived", true),
		repo("other-org/app", false),
	}
	env.gh.prs["mvdatacenter/app"] = []pullRequest{
		makePR(10, "alice", "mvdatacenter/app", "mvdatacenter/app", "feat/deps", "s10", "b"),
		makePR(11, "dependabot[bot]", "fork/app", "mvdatacenter/app", "dependabot/hapi", "s11", "b"),
		makePR(12, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/code", "s12", "b"),
		makePR(13, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/pkgonly", "s13", "b"),
		makePR(14, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/race", "s14", "b"),
		makePR(15, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/ok1", "s15", "b"),
		makePR(16, "dependabot[bot]", "mvdatacenter/app", "mvdatacenter/app", "dependabot/ok2", "s16", "b"),
	}
	env.gh.prFiles["mvdatacenter/app#12"] = []pullFile{
		{Filename: "yarn.lock", Status: "modified"},
		{Filename: "src/index.js", Status: "modified"},
	}
	env.gh.prFiles["mvdatacenter/app#13"] = []pullFile{
		{Filename: "package.json", Status: "modified"},
	}
	for _, n := range []int{14, 15, 16} {
		env.gh.prFiles[fmt.Sprintf("mvdatacenter/app#%d", n)] = []pullFile{
			{Filename: "package.json", Status: "modified"},
			{Filename: "yarn.lock", Status: "modified"},
		}
		sha := fmt.Sprintf("s%d", n)
		env.gh.files["mvdatacenter/app@"+sha+":package.json"] = pkgJSON
		env.gh.files["mvdatacenter/app@"+sha+":yarn.lock"] = heldLock
	}

	env.gh.rejectNextRef422 = true
	if err := env.run.run(context.Background()); err != nil {
		t.Fatalf("run with 422 race and write cap failed: %v", err)
	}
	committedRefs := []string{}
	for _, u := range env.gh.refUpdates {
		if u.Ref != "" {
			committedRefs = append(committedRefs, u.Ref)
		}
	}
	if len(committedRefs) != 1 || committedRefs[0] != "dependabot/ok1" {
		t.Fatalf("committed refs = %v, want [dependabot/ok1]", committedRefs)
	}

	unreadyGW := newTestEnv(t, Upstream{Name: "npm", Ecosystem: "npm", URL: env.reg.srv.URL, Hold: Duration{30 * day}, Advisories: "malicious"})
	env.cfg.Gateway = unreadyGW.srv.URL
	failRun, err := newClampRun(env.cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := failRun.run(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected 503 error on unready gateway, got %v", err)
	}
	if len(env.gh.comments["mvdatacenter/app#16"]) != 0 {
		t.Errorf("unready gateway wrote comments on PR #16")
	}
}
