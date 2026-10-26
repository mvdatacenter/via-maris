package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakePyPI struct {
	index, files *httptest.Server
	project      string
	uploads      map[string]time.Duration // filename -> age
	offHost      string                   // a filename listed on another host
	filesBase    string
}

func newFakePyPI(t *testing.T, project string, uploads map[string]time.Duration) *fakePyPI {
	f := &fakePyPI{project: project, uploads: uploads}
	f.files = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("file " + strings.TrimPrefix(r.URL.Path, "/")))
	}))
	f.index = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := f.files.URL
		if f.filesBase != "" {
			base = f.filesBase
		}
		if r.URL.Path == "/pypi/"+f.project+"/json" {
			f.serveJSON(w, base)
			return
		}
		if r.URL.Path != "/simple/"+f.project+"/" {
			http.NotFound(w, r)
			return
		}
		var files []map[string]any
		for name, age := range f.uploads {
			files = append(files, map[string]any{
				"filename":      name,
				"url":           base + "/packages/ab/" + name,
				"hashes":        map[string]string{"sha256": "00"},
				"upload-time":   ago(age),
				"core-metadata": map[string]string{"sha256": "11"},
			})
		}
		if f.offHost != "" {
			files = append(files, map[string]any{"filename": f.offHost, "url": "https://elsewhere.invalid/" + f.offHost, "upload-time": ago(100 * day)})
		}
		w.Header().Set("Content-Type", simpleJSON)
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.1"}, "name": f.project, "files": files})
	}))
	t.Cleanup(f.index.Close)
	t.Cleanup(f.files.Close)
	return f
}

func (f *fakePyPI) serveJSON(w http.ResponseWriter, base string) {
	releases := map[string][]map[string]any{}
	for name, age := range f.uploads {
		_, v, _ := pypiFilename(name)
		releases[v] = append(releases[v], map[string]any{
			"filename":             name,
			"url":                  base + "/packages/ab/" + name,
			"upload_time_iso_8601": ago(age),
			"yanked":               false,
			"yanked_reason":        nil,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"info": map[string]string{"name": f.project}, "releases": releases, "urls": []any{}})
}

func pypiUpstream(f *fakePyPI) Upstream {
	return Upstream{Name: "pypi", Ecosystem: "PyPI", URL: f.index.URL, Files: f.files.URL, Hold: Duration{7 * day}, Advisories: "malicious"}
}

func TestPyPISimpleYanksRefusedFilesAndKeepsDownloadsOnTheGateway(t *testing.T) {
	f := newFakePyPI(t, "boto3", map[string]time.Duration{
		"boto3-1.0.0-py3-none-any.whl": 100 * day,
		"boto3-1.1.0.tar.gz":           day,
	})
	f.offHost = "boto3-0.9.0.tar.gz"
	env := newTestEnv(t, pypiUpstream(f))
	env.loadAdvisories()

	status, body := env.get("/pypi/simple/Boto3/", "Accept", simpleJSON)
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	var doc struct{ Files []map[string]any }
	json.Unmarshal([]byte(body), &doc)
	if len(doc.Files) != 2 {
		t.Fatalf("files %v, want the two on the files host", doc.Files)
	}
	for _, file := range doc.Files {
		name := file["filename"].(string)
		if want := env.srv.URL + "/pypi/files/packages/ab/" + name; file["url"] != want {
			t.Errorf("url %v, want %s", file["url"], want)
		}
		yanked, _ := file["yanked"].(string)
		if name == "boto3-1.1.0.tar.gz" {
			wantContains(t, yanked, "via-maris refused boto3@1.1.0: published ")
		} else if yanked != "" {
			t.Errorf("%s yanked: %q", name, yanked)
		}
	}

	status, body = env.get("/pypi/simple/boto3/")
	if status != http.StatusOK {
		t.Fatalf("html: %d", status)
	}
	wantContains(t, body,
		`href="`+env.srv.URL+`/pypi/files/packages/ab/boto3-1.0.0-py3-none-any.whl#sha256=00"`,
		`data-core-metadata="sha256=11"`,
		`data-yanked="via-maris refused boto3@1.1.0: published `)
}

// rawGet returns the status line, because pip prints the reason phrase.
func rawGet(t *testing.T, base, path string) (statusLine, body string) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, strings.TrimPrefix(base, "http://"))
	r := bufio.NewReader(conn)
	statusLine, _ = r.ReadString('\n')
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(statusLine+readAll(r))), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return strings.TrimSpace(statusLine), readAll(bufio.NewReader(resp.Body))
}

func readAll(r *bufio.Reader) string {
	var b strings.Builder
	r.WriteTo(&b)
	return b.String()
}

func TestPyPIFileIsCheckedAgainstItsIndexEntry(t *testing.T) {
	f := newFakePyPI(t, "nvidia-clara-sim", map[string]time.Duration{
		"nvidia_clara_sim-0.0.0a0-py3-none-any.whl": 100 * day,
		"nvidia_clara_sim-0.0.1-py3-none-any.whl":   100 * day,
	})
	env := newTestEnv(t, pypiUpstream(f))
	env.osv.set(t, "PyPI", osvJSON("MAL-2024-10315", "PyPI", "nvidia-clara-sim", []string{"0.0.0a0"}))
	env.loadAdvisories()

	line, body := rawGet(t, env.srv.URL, "/pypi/files/packages/ab/nvidia_clara_sim-0.0.0a0-py3-none-any.whl")
	if line != "HTTP/1.1 403 via-maris refused nvidia-clara-sim@0.0.0a0: listed as malicious by MAL-2024-10315" {
		t.Errorf("status line %q", line)
	}
	wantContains(t, body, "listed as malicious by MAL-2024-10315")

	// Core metadata of a refused file is served, so the resolver can report
	// the yank reason.
	status, body := env.get("/pypi/files/packages/ab/nvidia_clara_sim-0.0.0a0-py3-none-any.whl.metadata")
	if status != http.StatusOK || body != "file packages/ab/nvidia_clara_sim-0.0.0a0-py3-none-any.whl.metadata" {
		t.Errorf("metadata: %d %q", status, body)
	}

	status, body = env.get("/pypi/files/packages/ab/nvidia_clara_sim-0.0.1-py3-none-any.whl")
	if status != http.StatusOK || body != "file packages/ab/nvidia_clara_sim-0.0.1-py3-none-any.whl" {
		t.Errorf("allowed file: %d %q", status, body)
	}

	// A path the index does not list is refused even for a known project.
	line, _ = rawGet(t, env.srv.URL, "/pypi/files/packages/zz/nvidia_clara_sim-0.0.1-py3-none-any.whl")
	wantContains(t, line, "403 via-maris refused nvidia-clara-sim@nvidia_clara_sim-0.0.1-py3-none-any.whl: no project index lists this file")
}

func TestPyPIFilename(t *testing.T) {
	for _, c := range []struct{ file, project, version string }{
		{"boto3-1.43.114-py3-none-any.whl", "boto3", "1.43.114"},
		{"Django-5.0.tar.gz", "django", "5.0"},
		{"zope.interface-6.1.zip", "zope-interface", "6.1"},
		{"my_pkg-2.0rc1.tar.bz2", "my-pkg", "2.0rc1"},
	} {
		p, v, ok := pypiFilename(c.file)
		if !ok || p != c.project || v != c.version {
			t.Errorf("pypiFilename(%q) = %q %q %v", c.file, p, v, ok)
		}
	}
	for _, bad := range []string{"README", "pkg.whl", "pkg-.tar.gz", "-1.0.tar.gz"} {
		if _, _, ok := pypiFilename(bad); ok {
			t.Errorf("pypiFilename(%q) parsed", bad)
		}
	}
}
