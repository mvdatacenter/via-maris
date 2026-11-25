package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowWrite is how long each write on the files host's first connection
// takes. It stands for the one degraded connection every download shared,
// as docs/configuration.md "Operating" describes.
const slowWrite = 500 * time.Millisecond

type slowFirstListener struct {
	net.Listener
	once sync.Once
}

func (l *slowFirstListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	slow := false
	l.once.Do(func() { slow = true })
	if slow {
		return slowConn{c}, nil
	}
	return c, nil
}

type slowConn struct{ net.Conn }

func (c slowConn) Write(b []byte) (int, error) {
	time.Sleep(slowWrite)
	return c.Conn.Write(b)
}

// newSlowFirstFilesHost offers HTTP/2, as files.pythonhosted.org does.
func newSlowFirstFilesHost(t *testing.T) (srv *httptest.Server, protos func() []int) {
	var mu sync.Mutex
	var seen []int
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.ProtoMajor)
		mu.Unlock()
		w.Write([]byte("file " + strings.TrimPrefix(r.URL.Path, "/")))
	}))
	srv.EnableHTTP2 = true
	srv.Listener = &slowFirstListener{Listener: srv.Listener}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), seen...)
	}
}

// downloadAll first fetches one wheel alone, so the files host's slow first
// connection is the one the client holds, as the gateway held its connection
// to files.pythonhosted.org for days. It then fetches every wheel through the
// gateway at once, as a CI job's installer does, and returns how long each
// took.
func downloadAll(env *testEnv, wheels []string) []time.Duration {
	if status, body := env.get("/pypi/files/packages/ab/" + wheels[0]); status != http.StatusOK {
		env.t.Fatalf("first download: %d %q", status, body)
	}
	took := make([]time.Duration, len(wheels))
	var wg sync.WaitGroup
	for i, name := range wheels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			status, body := env.get("/pypi/files/packages/ab/" + name)
			took[i] = time.Since(start)
			if status != http.StatusOK || body != "file packages/ab/"+name {
				env.t.Errorf("%s: %d %q", name, status, body)
			}
		}()
	}
	wg.Wait()
	return took
}

func slowCount(took []time.Duration) int {
	n := 0
	for _, d := range took {
		if d >= slowWrite/2 {
			n++
		}
	}
	return n
}

func TestUpstreamDownloadsDoNotQueueBehindOneSlowConnection(t *testing.T) {
	const n = 6
	uploads := map[string]time.Duration{}
	var wheels []string
	for i := range n {
		name := fmt.Sprintf("six-1.%d.0-py3-none-any.whl", i)
		uploads[name] = 100 * day
		wheels = append(wheels, name)
	}

	// The gateway's client up to v0.1.7: a Transport left to Go's defaults,
	// which negotiates HTTP/2 with a host that offers it. The test names
	// HTTP/2 explicitly because trusting the test CA sets TLSClientConfig,
	// which turns the default off.
	t.Run("HTTP/2 client queues every download behind the slow connection", func(t *testing.T) {
		files, protos := newSlowFirstFilesHost(t)
		f := newFakePyPI(t, "six", uploads)
		f.filesBase = files.URL
		client := newUpstreamClient()
		tr := client.Transport.(*http.Transport)
		tr.TLSClientConfig = files.Client().Transport.(*http.Transport).TLSClientConfig
		var both http.Protocols
		both.SetHTTP1(true)
		both.SetHTTP2(true)
		tr.Protocols = &both
		env := newTestEnvWithClient(t, client, Upstream{Name: "pypi", Ecosystem: "PyPI", URL: f.index.URL, Files: files.URL, Hold: Duration{7 * day}, Advisories: "malicious"})
		env.loadAdvisories()

		took := downloadAll(env, wheels)
		if got := slowCount(took); got != n {
			t.Fatalf("%d of %d downloads slow (%v), want all: the reproduction no longer reproduces", got, n, took)
		}
		for _, p := range protos() {
			if p != 2 {
				t.Fatalf("files host saw HTTP/%d, want HTTP/2 throughout", p)
			}
		}
	})

	t.Run("gateway client gives each download a connection of its own", func(t *testing.T) {
		files, protos := newSlowFirstFilesHost(t)
		f := newFakePyPI(t, "six", uploads)
		f.filesBase = files.URL
		client := newUpstreamClient()
		client.Transport.(*http.Transport).TLSClientConfig = files.Client().Transport.(*http.Transport).TLSClientConfig
		env := newTestEnvWithClient(t, client, Upstream{Name: "pypi", Ecosystem: "PyPI", URL: f.index.URL, Files: files.URL, Hold: Duration{7 * day}, Advisories: "malicious"})
		env.loadAdvisories()

		took := downloadAll(env, wheels)
		if got := slowCount(took); got > 1 {
			t.Fatalf("%d of %d downloads slow (%v), want at most the one on the slow connection", got, n, took)
		}
		for _, p := range protos() {
			if p != 1 {
				t.Fatalf("files host saw HTTP/%d, want HTTP/1.1 throughout", p)
			}
		}

		// The first download alone, then the n at once.
		_, metrics := env.get("/metrics")
		host := strings.TrimPrefix(files.URL, "https://")
		wantContains(t, metrics,
			fmt.Sprintf("via_maris_upstream_response_seconds_count{host=%q} %d\n", host, n+1),
			fmt.Sprintf("via_maris_upstream_response_seconds_bucket{host=%q,le=\"+Inf\"} %d\n", host, n+1),
			fmt.Sprintf("via_maris_upstream_response_seconds_bucket{host=%q,le=\"0.25\"} ", host))
	})
}

func TestResponseTimesRendersCumulativeBuckets(t *testing.T) {
	rt := newResponseTimes()
	rt.observe("files.example", 100*time.Millisecond)
	rt.observe("files.example", 3*time.Second)
	rt.observe("files.example", time.Minute)
	var b strings.Builder
	rt.metrics(&b)
	wantContains(t, b.String(),
		`via_maris_upstream_response_seconds_bucket{host="files.example",le="0.25"} 1`+"\n",
		`via_maris_upstream_response_seconds_bucket{host="files.example",le="2.5"} 1`+"\n",
		`via_maris_upstream_response_seconds_bucket{host="files.example",le="5"} 2`+"\n",
		`via_maris_upstream_response_seconds_bucket{host="files.example",le="30"} 2`+"\n",
		`via_maris_upstream_response_seconds_bucket{host="files.example",le="+Inf"} 3`+"\n",
		`via_maris_upstream_response_seconds_count{host="files.example"} 3`+"\n")
}
