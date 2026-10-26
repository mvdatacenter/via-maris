package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	pem  []byte
}

func newTestCA(t *testing.T, names ...string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     pkix.Name{CommonName: "via-maris test CA"},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(10 * 365 * day),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, key, pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) writeLeaf(t *testing.T, dir string, serial int64, life time.Duration, names ...string) time.Time {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(life).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	for name, b := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"ca.crt":  ca.pem,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return notAfter
}

type byNameEnv struct {
	*testEnv
	ca       *testCA
	certDir  string
	tlsAddr  string
	leafExp  time.Time
	pypiPort string
}

func newByNameEnv(t *testing.T, uploads map[string]time.Duration) *byNameEnv {
	t.Helper()
	f := newFakePyPI(t, "boto3", uploads)
	indexPort := f.index.URL[strings.LastIndex(f.index.URL, ":")+1:]
	filesPort := f.files.URL[strings.LastIndex(f.files.URL, ":")+1:]
	f.filesBase = "http://files.test:" + filesPort
	up := Upstream{Name: "pypi", Ecosystem: "PyPI", URL: "http://pypi.test:" + indexPort, Files: f.filesBase, Hold: Duration{7 * day}, Advisories: "malicious"}
	env := &byNameEnv{testEnv: newTestEnv(t, up), ca: newTestCA(t, "pypi.test", "files.test"), certDir: t.TempDir()}
	env.leafExp = env.ca.writeLeaf(t, env.certDir, 2, 30*day, "pypi.test", "files.test")
	env.g.client = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if host == "pypi.test" || host == "files.test" {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}}
	env.g.cfg.ByName = &ByName{Listen: "127.0.0.1:0", Upstream: "pypi", Cert: filepath.Join(env.certDir, "tls.crt"), Key: filepath.Join(env.certDir, "tls.key"), CA: filepath.Join(env.certDir, "ca.crt")}
	if err := env.g.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	env.g.byName = newByName(env.g, env.g.cfg.ByName)
	env.srv.Config.Handler = env.g.handler()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.tlsAddr = ln.Addr().String()
	go env.g.byName.serveTLS(ln)
	t.Cleanup(func() { env.g.byName.srv.Close() })
	env.loadAdvisories()
	return env
}

func (env *byNameEnv) proxied() *http.Client {
	proxy, _ := url.Parse(env.srv.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: env.ca.pool}}}
}

func (env *byNameEnv) mapped() *http.Client {
	_, port, _ := net.SplitHostPort(env.tlsAddr)
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: env.ca.pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}}
}

func fetchBody(t *testing.T, c *http.Client, u string, header ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestByNameKeepsLockfileURLsAndChecksEachFile(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{
		"boto3-1.0.0-py3-none-any.whl": 100 * day,
		"boto3-1.1.0.tar.gz":           day,
	})
	for name, c := range map[string]*http.Client{"CONNECT": env.proxied(), "mapped": env.mapped()} {
		t.Run(name, func(t *testing.T) {
			resp, body := fetchBody(t, c, "https://pypi.test/simple/Boto3/", "Accept", simpleJSON)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
			var doc struct{ Files []map[string]any }
			json.Unmarshal([]byte(body), &doc)
			if len(doc.Files) != 2 {
				t.Fatalf("files %v", doc.Files)
			}
			for _, file := range doc.Files {
				name := file["filename"].(string)
				if want := env.g.byName.up.Files + "/packages/ab/" + name; file["url"] != want {
					t.Errorf("url %v, want %s", file["url"], want)
				}
				yanked, _ := file["yanked"].(string)
				if name == "boto3-1.1.0.tar.gz" {
					wantContains(t, yanked, "via-maris refused boto3@1.1.0: published ")
				} else if yanked != "" {
					t.Errorf("%s yanked: %q", name, yanked)
				}
			}

			resp, body = fetchBody(t, c, "https://files.test/packages/ab/boto3-1.0.0-py3-none-any.whl")
			if resp.StatusCode != http.StatusOK || body != "file packages/ab/boto3-1.0.0-py3-none-any.whl" {
				t.Errorf("allowed file: %d %q", resp.StatusCode, body)
			}
			resp, body = fetchBody(t, c, "https://files.test/packages/ab/boto3-1.1.0.tar.gz")
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("held file: %d %q", resp.StatusCode, body)
			}
			wantContains(t, resp.Status, "via-maris refused boto3@1.1.0: published ")
			if r := env.lastRecord(); r.Kind != "artifact" || r.Served || r.Version != "1.1.0" {
				t.Errorf("record %+v", r)
			}
		})
	}
}

func TestByNameJSONAPIYanksRefusedFiles(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{
		"boto3-1.0.0-py3-none-any.whl": 100 * day,
		"boto3-1.1.0.tar.gz":           day,
	})
	resp, body := fetchBody(t, env.mapped(), "https://pypi.test/pypi/boto3/json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var doc struct {
		Releases map[string][]map[string]any
		URLs     []any
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if f := doc.Releases["1.0.0"][0]; f["yanked"] != false {
		t.Errorf("1.0.0: %v", f)
	}
	f := doc.Releases["1.1.0"][0]
	if f["yanked"] != true {
		t.Errorf("1.1.0 not yanked: %v", f)
	}
	wantContains(t, fmt.Sprint(f["yanked_reason"]), "via-maris refused boto3@1.1.0: published ")
	if doc.URLs == nil {
		t.Error("urls encoded as null, want an empty list")
	}
}

func TestByNameJSONAPIEscapesPathSegmentsUpstream(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{"boto3-1.0.0-py3-none-any.whl": 100 * day})
	resp, body := fetchBody(t, env.mapped(), "https://pypi.test/pypi/boto3/json%3F/json")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("%d %s, want 404: a decoded ? must not reach the upstream as a query", resp.StatusCode, body)
	}
}

func TestByNameRefusesOtherNames(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{"boto3-1.0.0-py3-none-any.whl": 100 * day})

	conn, err := net.Dial("tcp", strings.TrimPrefix(env.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT github.com: %d", resp.StatusCode)
	}
	wantContains(t, string(b), "via-maris refused CONNECT to github.com:443: CONNECT reaches pypi.test:443 and files.test:443 alone")
	if r := env.lastRecord(); r.Kind != "connect" || r.Served || r.Package != "github.com:443" {
		t.Errorf("record %+v", r)
	}

	_, err = tls.Dial("tcp", env.tlsAddr, &tls.Config{ServerName: "github.com", RootCAs: env.ca.pool})
	if err == nil {
		t.Error("handshake for github.com completed")
	}
}

func TestByNameReloadsARenewedLeafAndReportsExpiry(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{"boto3-1.0.0-py3-none-any.whl": 100 * day})
	presented := func() *x509.Certificate {
		t.Helper()
		c, err := tls.Dial("tcp", env.tlsAddr, &tls.Config{ServerName: "pypi.test", RootCAs: env.ca.pool})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0]
	}
	if got := presented(); got.SerialNumber.Int64() != 2 {
		t.Fatalf("serial %v", got.SerialNumber)
	}
	_, metrics := env.get("/metrics")
	wantContains(t, metrics,
		fmt.Sprintf("via_maris_tls_expiry_timestamp_seconds{certificate=\"leaf\"} %d\n", env.leafExp.Unix()),
		fmt.Sprintf("via_maris_tls_expiry_timestamp_seconds{certificate=\"ca\"} %d\n", env.ca.cert.NotAfter.Unix()))

	renewed := env.ca.writeLeaf(t, env.certDir, 3, 40*day, "pypi.test", "files.test")
	later := time.Now().Add(time.Minute)
	for _, n := range []string{"tls.crt", "tls.key"} {
		os.Chtimes(filepath.Join(env.certDir, n), later, later)
	}
	if got := presented(); got.SerialNumber.Int64() != 3 {
		t.Errorf("after renewal serial %v, want 3", got.SerialNumber)
	}
	_, metrics = env.get("/metrics")
	wantContains(t, metrics, fmt.Sprintf("via_maris_tls_expiry_timestamp_seconds{certificate=\"leaf\"} %d\n", renewed.Unix()))

	os.WriteFile(filepath.Join(env.certDir, "tls.key"), []byte("garbage"), 0o600)
	if got := presented(); got.SerialNumber.Int64() != 3 {
		t.Errorf("after a broken write serial %v, want 3", got.SerialNumber)
	}
}

func TestByNameNotReadyWithoutACertificate(t *testing.T) {
	env := newByNameEnv(t, map[string]time.Duration{"boto3-1.0.0-py3-none-any.whl": 100 * day})
	env.g.byName.certs = &certFiles{cert: filepath.Join(env.certDir, "absent.crt"), key: filepath.Join(env.certDir, "absent.key"), ca: filepath.Join(env.certDir, "ca.crt")}
	status, body := env.get("/healthz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("healthz %d %s", status, body)
	}
	wantContains(t, body, "tls certificate")
	_, metrics := env.get("/metrics")
	wantContains(t, metrics, "via_maris_tls_expiry_timestamp_seconds{certificate=\"leaf\"} 0\n")
}
