package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is an S3-compatible bucket in memory. It checks that every
// request carries a signature for the expected key, and fails on demand.
type fakeStore struct {
	mu        sync.Mutex
	objects   map[string][]byte
	fail      bool
	beforePut func(objects map[string][]byte, key string)
}

func etagOf(b []byte) string { return fmt.Sprintf("%q", fmt.Sprintf("%x", sha256.Sum256(b))) }

func newFakeStore(t *testing.T) (*fakeStore, *httptest.Server) {
	s := &fakeStore{objects: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=test-key/") {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.fail {
			http.Error(w, "store down", http.StatusInternalServerError)
			return
		}
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			if s.beforePut != nil {
				s.beforePut(s.objects, r.URL.Path)
			}
			cur, exists := s.objects[r.URL.Path]
			if m := r.Header.Get("If-Match"); m != "" && (!exists || m != etagOf(cur)) ||
				r.Header.Get("If-None-Match") == "*" && exists {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			s.objects[r.URL.Path] = b
		case http.MethodGet:
			if r.URL.Query().Get("list-type") == "2" {
				s.list(w, r)
				return
			}
			b, ok := s.objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", etagOf(b))
			w.Write(b)
		}
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

// list answers ListObjectsV2 two keys a page, so callers must follow the
// continuation token. The token is the last key of the page.
func (s *fakeStore) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bucket := strings.TrimSuffix(r.URL.Path, "/") + "/"
	after := q.Get("start-after")
	if tok := q.Get("continuation-token"); tok != "" {
		after = tok
	}
	var keys []string
	for k := range s.objects {
		key, ok := strings.CutPrefix(k, bucket)
		if ok && strings.HasPrefix(key, q.Get("prefix")) && key > after {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	page, truncated := keys, false
	if len(keys) > 2 {
		page, truncated = keys[:2], true
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	for _, k := range page {
		b.WriteString("<Contents><Key>" + k + "</Key></Contents>")
	}
	fmt.Fprintf(&b, "<IsTruncated>%t</IsTruncated>", truncated)
	if truncated {
		b.WriteString("<NextContinuationToken>" + page[len(page)-1] + "</NextContinuationToken>")
	}
	b.WriteString("</ListBucketResult>")
	w.Write([]byte(b.String()))
}

func (s *fakeStore) setFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

func (s *fakeStore) put(key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = body
}

func (s *fakeStore) keys(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

type osvExport struct {
	mu   sync.Mutex
	zips map[string][]byte
}

func newOSVExport(t *testing.T) (*osvExport, *httptest.Server) {
	e := &osvExport{zips: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco, _ := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/all.zip")
		e.mu.Lock()
		b, ok := e.zips[eco]
		e.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return e, srv
}

func (e *osvExport) set(t *testing.T, eco string, entries ...string) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, entry := range entries {
		f, err := zw.Create(strings.Repeat("x", i+1) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(entry))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.zips[eco] = buf.Bytes()
	e.mu.Unlock()
}

func osvJSON(id, eco, pkg string, versions []string, ranges ...[]map[string]string) string {
	var rs []map[string]any
	for _, events := range ranges {
		rs = append(rs, map[string]any{"type": "ECOSYSTEM", "events": events})
	}
	b, _ := json.Marshal(map[string]any{
		"id": id,
		"affected": []map[string]any{{
			"package":  map[string]string{"ecosystem": eco, "name": pkg},
			"versions": versions,
			"ranges":   rs,
		}},
	})
	return string(b)
}

func ev(kind, at string) map[string]string { return map[string]string{kind: at} }

type testEnv struct {
	t       *testing.T
	g       *gateway
	srv     *httptest.Server
	osv     *osvExport
	store   *fakeStore
	records bytes.Buffer
}

func newTestEnv(t *testing.T, upstreams ...Upstream) *testEnv {
	t.Helper()
	t.Setenv("TEST_KEY_ID", "test-key")
	t.Setenv("TEST_SECRET", "test-secret")
	env := &testEnv{t: t}
	var osvSrv, storeSrv *httptest.Server
	env.osv, osvSrv = newOSVExport(t)
	env.store, storeSrv = newFakeStore(t)
	store := Store{Endpoint: storeSrv.URL, Region: "test", Bucket: "bucket", AccessKeyIDEnv: "TEST_KEY_ID", SecretAccessKeyEnv: "TEST_SECRET"}
	cfg := &Config{Listen: ":0", Upstreams: upstreams}
	cfg.Advisories.Source = osvSrv.URL
	cfg.Advisories.Refresh = Duration{time.Minute}
	cfg.Advisories.MaxAge = Duration{time.Hour}
	cfg.InUse.Store = store
	cfg.InUse.Object = "in-use.json"
	cfg.InUse.Refresh = Duration{time.Minute}
	cfg.InUse.MaxAge = Duration{time.Hour}
	cfg.Records.Store = store
	cfg.Records.Prefix = "records/"
	cfg.Records.Interval = Duration{time.Second}
	cfg.Records.MaxUnshipped = Duration{time.Minute}
	if err := cfg.validate(); err != nil {
		t.Fatalf("test configuration: %v", err)
	}
	g, err := newGateway(cfg, http.DefaultClient, &env.records)
	if err != nil {
		t.Fatal(err)
	}
	env.g = g
	env.srv = httptest.NewServer(g.handler())
	t.Cleanup(env.srv.Close)
	return env
}

func (env *testEnv) loadAdvisories() {
	env.t.Helper()
	for _, eco := range env.g.ecosystems {
		if _, ok := env.osv.zips[eco]; !ok {
			env.osv.set(env.t, eco)
		}
		if err := env.g.db.load(context.Background(), eco); err != nil {
			env.t.Fatal(err)
		}
	}
}

func (env *testEnv) setInUse(generated time.Time, ecosystems map[string]map[string][]string) {
	env.t.Helper()
	b, _ := json.Marshal(inUseFile{Generated: generated, Ecosystems: ecosystems})
	env.store.put("/bucket/in-use.json", b)
	if err := env.g.inUse.load(context.Background()); err != nil {
		env.t.Fatal(err)
	}
}

func (env *testEnv) get(path string, header ...string) (int, string) {
	env.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (env *testEnv) lastRecord() record {
	env.t.Helper()
	env.g.records.mu.Lock()
	lines := strings.Split(strings.TrimSpace(env.records.String()), "\n")
	env.g.records.mu.Unlock()
	var r record
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		env.t.Fatalf("record %q: %v", lines[len(lines)-1], err)
	}
	return r
}

func ago(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

const day = 24 * time.Hour

func wantContains(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("got %q, want it to contain %q", got, w)
		}
	}
}
