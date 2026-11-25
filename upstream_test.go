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
const slowWrite = 200 * time.Millisecond

type slowFirstListener struct {
	net.Listener
	once sync.Once
	mu   sync.Mutex
	slow string
}

func (l *slowFirstListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	first := false
	l.once.Do(func() { first = true })
	if !first {
		return c, nil
	}
	l.mu.Lock()
	l.slow = c.RemoteAddr().String()
	l.mu.Unlock()
	return slowConn{c}, nil
}

func (l *slowFirstListener) slowAddr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.slow
}

type slowConn struct{ net.Conn }

func (c slowConn) Write(b []byte) (int, error) {
	time.Sleep(slowWrite)
	return c.Conn.Write(b)
}

// filesHost records, for each request, its protocol and whether it arrived
// on the slow connection. Once armed for n requests, it holds each one until
// all n are in flight, so they need n streams at once.
type filesHost struct {
	srv  *httptest.Server
	ln   *slowFirstListener
	mu   sync.Mutex
	reqs []filesRequest
	wait int
	all  chan struct{}
}

type filesRequest struct {
	proto  int
	onSlow bool
}

func newFilesHost(t *testing.T) *filesHost {
	h := &filesHost{}
	h.srv = httptest.NewUnstartedServer(http.HandlerFunc(h.serve))
	h.srv.EnableHTTP2 = true
	h.ln = &slowFirstListener{Listener: h.srv.Listener}
	h.srv.Listener = h.ln
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	return h
}

func (h *filesHost) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.reqs = append(h.reqs, filesRequest{proto: r.ProtoMajor, onSlow: r.RemoteAddr == h.ln.slowAddr()})
	all := h.all
	if all != nil {
		h.wait--
		if h.wait == 0 {
			close(all)
		}
	}
	h.mu.Unlock()
	if all != nil {
		select {
		case <-all:
		case <-time.After(time.Minute):
		}
	}
	w.Write([]byte("file " + strings.TrimPrefix(r.URL.Path, "/")))
}

func (h *filesHost) arm(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reqs = nil
	h.wait = n
	h.all = make(chan struct{})
}

func (h *filesHost) requests() []filesRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]filesRequest(nil), h.reqs...)
}

// upstreamClientFor is newUpstreamClient trusting the files host's test CA.
// Setting TLSClientConfig turns off the HTTP/2 Go attempts by default, so
// ForceAttemptHTTP2 turns it back on, as the production client has it with
// no TLSClientConfig.
func upstreamClientFor(h *filesHost) *http.Client {
	client := newUpstreamClient()
	tr := client.Transport.(*http.Transport)
	tr.TLSClientConfig = h.srv.Client().Transport.(*http.Transport).TLSClientConfig
	tr.ForceAttemptHTTP2 = true
	return client
}

// downloadAll first fetches one wheel alone, so the files host's slow first
// connection is the one the client holds, as the gateway held its connection
// to files.pythonhosted.org. It then fetches every wheel through the gateway
// at once, as a CI job's installer does, and returns what the files host saw
// of those parallel requests.
func downloadAll(env *testEnv, h *filesHost, wheels []string) []filesRequest {
	if status, body := env.get("/pypi/files/packages/ab/" + wheels[0]); status != http.StatusOK {
		env.t.Fatalf("first download: %d %q", status, body)
	}
	h.arm(len(wheels))
	var wg sync.WaitGroup
	for _, name := range wheels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body := env.get("/pypi/files/packages/ab/" + name)
			if status != http.StatusOK || body != "file packages/ab/"+name {
				env.t.Errorf("%s: %d %q", name, status, body)
			}
		}()
	}
	wg.Wait()
	return h.requests()
}

func onSlowCount(reqs []filesRequest) int {
	n := 0
	for _, r := range reqs {
		if r.onSlow {
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
	newEnv := func(t *testing.T, h *filesHost, client *http.Client) *testEnv {
		f := newFakePyPI(t, "six", uploads)
		f.filesBase = h.srv.URL
		env := newTestEnvWithClient(t, client, Upstream{Name: "pypi", Ecosystem: "PyPI", URL: f.index.URL, Files: h.srv.URL, Hold: Duration{7 * day}, Advisories: "malicious"})
		env.loadAdvisories()
		return env
	}

	// The gateway's client up to v0.1.7 set no Protocols, so Go negotiated
	// HTTP/2 with a host offering it.
	t.Run("HTTP/2 client queues every download behind the slow connection", func(t *testing.T) {
		h := newFilesHost(t)
		client := upstreamClientFor(h)
		client.Transport.(*http.Transport).Protocols = nil
		reqs := downloadAll(newEnv(t, h, client), h, wheels)
		if len(reqs) != n || onSlowCount(reqs) != n {
			t.Fatalf("%d of %d parallel downloads on the slow connection (%+v), want all: the reproduction no longer reproduces", onSlowCount(reqs), n, reqs)
		}
		for _, r := range reqs {
			if r.proto != 2 {
				t.Fatalf("files host saw HTTP/%d, want HTTP/2 throughout", r.proto)
			}
		}
	})

	t.Run("gateway client gives each download a connection of its own", func(t *testing.T) {
		h := newFilesHost(t)
		env := newEnv(t, h, upstreamClientFor(h))
		reqs := downloadAll(env, h, wheels)
		if len(reqs) != n || onSlowCount(reqs) > 1 {
			t.Fatalf("%d of %d parallel downloads on the slow connection (%+v), want at most one", onSlowCount(reqs), n, reqs)
		}
		for _, r := range reqs {
			if r.proto != 1 {
				t.Fatalf("files host saw HTTP/%d, want HTTP/1.1 throughout", r.proto)
			}
		}

		// The first download alone, then the n at once.
		_, metrics := env.get("/metrics")
		host := strings.TrimPrefix(h.srv.URL, "https://")
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
