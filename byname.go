package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// byName is the front end "PyPI by its own names" in docs/configuration.md describes.
type byName struct {
	g                    *gateway
	up                   *Upstream
	indexHost, filesHost string
	indexPath, filesPath string
	certs                *certFiles
	tunnels              *tunnelListener
	srv                  *http.Server
}

func newByName(g *gateway, cfg *ByName) *byName {
	var up *Upstream
	for i := range g.cfg.Upstreams {
		if g.cfg.Upstreams[i].Name == cfg.Upstream {
			up = &g.cfg.Upstreams[i]
		}
	}
	index, _ := url.Parse(up.URL)
	files, _ := url.Parse(up.Files)
	b := &byName{
		g:         g,
		up:        up,
		indexHost: index.Hostname(),
		filesHost: files.Hostname(),
		indexPath: index.Path,
		filesPath: files.Path,
		certs:     &certFiles{cert: cfg.Cert, key: cfg.Key, ca: cfg.CA},
		tunnels:   newTunnelListener(),
	}
	b.srv = &http.Server{
		Handler:           g.gated(up, b.serve),
		ReadHeaderTimeout: 30 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: b.certificate},
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	return b
}

func (b *byName) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != b.indexHost && hello.ServerName != b.filesHost {
		return nil, fmt.Errorf("via-maris answers TLS for %s and %s alone, not %q", b.indexHost, b.filesHost, hello.ServerName)
	}
	return b.certs.current()
}

func (b *byName) serveTLS(ln net.Listener) error {
	served := make(chan error, 2)
	go func() { served <- b.srv.ServeTLS(ln, "", "") }()
	go func() { served <- b.srv.ServeTLS(b.tunnels, "", "") }()
	return <-served
}

func (b *byName) serve(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case b.indexHost:
		b.index(w, r)
	case b.filesHost:
		rel, ok := strings.CutPrefix(r.URL.Path, b.filesPath+"/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		b.g.pypiFile(w, r, b.up, rel)
	default:
		http.NotFound(w, r)
	}
}

func (b *byName) index(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, b.indexPath+"/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	for _, p := range parts {
		if p == "" || p == ".." {
			http.NotFound(w, r)
			return
		}
	}
	switch {
	case len(parts) == 2 && parts[0] == "simple":
		b.g.pypiSimple(w, r, b.up, normalizePyPI(parts[1]), func(rel string) string { return b.up.Files + "/" + rel })
	case len(parts) == 3 && parts[0] == "pypi" && parts[2] == "json":
		b.g.pypiJSON(w, r, b.up, normalizePyPI(parts[1]), "/pypi/"+url.PathEscape(parts[1])+"/json")
	case len(parts) == 4 && parts[0] == "pypi" && parts[3] == "json":
		b.g.pypiJSON(w, r, b.up, normalizePyPI(parts[1]), "/pypi/"+url.PathEscape(parts[1])+"/"+url.PathEscape(parts[2])+"/json")
	default:
		http.NotFound(w, r)
	}
}

func (b *byName) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" || host != b.indexHost && host != b.filesHost {
		vd := verdict{false, fmt.Sprintf("CONNECT reaches %s:443 and %s:443 alone", b.indexHost, b.filesHost)}
		b.g.record(r, b.up, "connect", r.Host, "", vd)
		http.Error(w, "via-maris refused CONNECT to "+r.Host+": "+vd.Reason, http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "via-maris: CONNECT needs HTTP/1", http.StatusHTTPVersionNotSupported)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	var c net.Conn = conn
	if buf.Reader.Buffered() > 0 {
		c = &bufConn{conn, buf.Reader}
	}
	b.tunnels.hand(c)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type tunnelListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newTunnelListener() *tunnelListener {
	return &tunnelListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *tunnelListener) hand(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *tunnelListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *tunnelListener) Addr() net.Addr { return tunnelAddr{} }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "connect" }
func (tunnelAddr) String() string  { return "connect" }

type certFiles struct {
	cert, key, ca string

	mu           sync.Mutex
	stamp        string
	pair         *tls.Certificate
	leafNotAfter time.Time
	caNotAfter   time.Time
}

func fileStamp(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s:%v;", p, err)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", p, fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String()
}

func (c *certFiles) current() (*tls.Certificate, error) {
	stamp := fileStamp(c.cert, c.key, c.ca)
	c.mu.Lock()
	defer c.mu.Unlock()
	if stamp == c.stamp && c.pair != nil {
		return c.pair, nil
	}
	pair, caNotAfter, err := loadCertFiles(c.cert, c.key, c.ca)
	if err != nil {
		if c.pair != nil {
			log.Printf("tls certificate: %v; still presenting the one that expires %s", err, c.leafNotAfter.Format(time.RFC3339))
			return c.pair, nil
		}
		return nil, err
	}
	c.stamp, c.pair = stamp, pair
	c.leafNotAfter, c.caNotAfter = pair.Leaf.NotAfter, caNotAfter
	log.Printf("tls certificate: loaded leaf for %s, expires %s; CA expires %s", strings.Join(pair.Leaf.DNSNames, ", "), c.leafNotAfter.Format(time.RFC3339), caNotAfter.Format(time.RFC3339))
	return pair, nil
}

func loadCertFiles(certPath, keyPath, caPath string) (*tls.Certificate, time.Time, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, time.Time{}, err
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, time.Time{}, err
		}
	}
	b, err := os.ReadFile(caPath)
	if err != nil {
		return nil, time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, time.Time{}, errors.New(caPath + " holds no PEM certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", caPath, err)
	}
	return &pair, ca.NotAfter, nil
}

func (c *certFiles) expiry() (leaf, ca time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leafNotAfter, c.caNotAfter
}

func (g *gateway) pypiJSON(w http.ResponseWriter, r *http.Request, up *Upstream, project, upstreamPath string) {
	resp, err := g.fetch(r.Context(), up.URL+upstreamPath, "application/json")
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		upstreamStatus(w, resp.StatusCode, project)
		return
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		upstreamError(w, fmt.Errorf("%s: %w", project, err))
		return
	}
	total, refused := 0, 0
	mark := func(listed []any) []any {
		files := []any{}
		for _, x := range listed {
			f, _ := x.(map[string]any)
			if f == nil || !strings.HasPrefix(fileField(f, "url"), up.Files+"/") {
				continue
			}
			total++
			v, vd := g.pypiFileVerdict(up, project, fileField(f, "filename"), fileField(f, "upload_time_iso_8601"))
			if !vd.Served {
				f["yanked"] = true
				f["yanked_reason"] = refusal(project, v, vd)
				refused++
			}
			files = append(files, f)
		}
		return files
	}
	if releases, ok := doc["releases"].(map[string]any); ok {
		for v, x := range releases {
			listed, _ := x.([]any)
			releases[v] = mark(listed)
		}
	}
	if listed, ok := doc["urls"].([]any); ok {
		doc["urls"] = mark(listed)
	}
	g.record(r, up, "metadata", project, "", verdict{true, fmt.Sprintf("%d of %d files refused", refused, total)})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
