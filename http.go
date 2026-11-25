package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (g *gateway) fetch(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "via-maris/"+version)
	return g.client.Do(req)
}

func (g *gateway) stream(w http.ResponseWriter, r *http.Request, url string) {
	start := time.Now()
	resp, err := g.fetch(r.Context(), url, r.Header.Get("Accept"))
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	g.upstream.observe(hostOf(url), time.Since(start))
	for _, h := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// hostOf names the host a configured upstream URL points at, rather than the
// host a redirect ends on, so the hosts a series is kept for are the
// configuration's.
func hostOf(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// responseTimeBuckets are the upper bounds, in seconds, of
// via_maris_upstream_response_seconds. A download usually has its response
// headers within a second; on 2026-11-25 they took 9 to 26 seconds
// (mvdatacenter/ansible-mining#2157).
var responseTimeBuckets = []float64{0.25, 0.5, 1, 2.5, 5, 10, 30}

type responseTimes struct {
	mu     sync.Mutex
	byHost map[string]*responseHistogram
}

type responseHistogram struct {
	buckets []uint64 // one per bound in responseTimeBuckets, not cumulative
	count   uint64
	sum     float64
}

func newResponseTimes() *responseTimes {
	return &responseTimes{byHost: map[string]*responseHistogram{}}
}

func (rt *responseTimes) observe(host string, d time.Duration) {
	s := d.Seconds()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	h := rt.byHost[host]
	if h == nil {
		h = &responseHistogram{buckets: make([]uint64, len(responseTimeBuckets))}
		rt.byHost[host] = h
	}
	h.count++
	h.sum += s
	for i, le := range responseTimeBuckets {
		if s <= le {
			h.buckets[i]++
			break
		}
	}
}

func (rt *responseTimes) metrics(w io.Writer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	hosts := make([]string, 0, len(rt.byHost))
	for host := range rt.byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		h := rt.byHost[host]
		var cum uint64
		for i, le := range responseTimeBuckets {
			cum += h.buckets[i]
			fmt.Fprintf(w, "via_maris_upstream_response_seconds_bucket{host=%q,le=%q} %d\n", host, strconv.FormatFloat(le, 'f', -1, 64), cum)
		}
		fmt.Fprintf(w, "via_maris_upstream_response_seconds_bucket{host=%q,le=\"+Inf\"} %d\n", host, h.count)
		fmt.Fprintf(w, "via_maris_upstream_response_seconds_sum{host=%q} %g\n", host, h.sum)
		fmt.Fprintf(w, "via_maris_upstream_response_seconds_count{host=%q} %d\n", host, h.count)
	}
}

func upstreamError(w http.ResponseWriter, err error) {
	http.Error(w, "via-maris: upstream unreachable: "+err.Error(), http.StatusBadGateway)
}

func upstreamStatus(w http.ResponseWriter, status int, what string) {
	http.Error(w, fmt.Sprintf("via-maris: upstream answered %d for %s", status, what), status)
}

// refuse answers 403 with the refusal as the body, as JSON for npm, which
// prints a JSON body's error field.
func refuse(w http.ResponseWriter, msg string, asJSON bool) {
	if asJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}

// refuseInStatus also writes the refusal as the status line's reason phrase,
// because pip prints the phrase and never the body. Go's server writes only
// standard phrases, so this takes over the HTTP/1 connection to write one.
func refuseInStatus(w http.ResponseWriter, r *http.Request, msg string) {
	hj, ok := w.(http.Hijacker)
	if !ok || r.ProtoMajor != 1 {
		refuse(w, msg, false)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		refuse(w, msg, false)
		return
	}
	defer conn.Close()
	phrase := strings.Map(func(c rune) rune {
		if c < 0x20 || c > 0x7e {
			return '?'
		}
		return c
	}, msg)
	body := msg + "\n"
	fmt.Fprintf(buf, "HTTP/1.1 403 %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", phrase, len(body), body)
	buf.Flush()
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (g *gateway) record(r *http.Request, up *Upstream, kind, pkg, version string, v verdict) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	var published string
	if !v.Published.IsZero() {
		published = v.Published.UTC().Format(time.RFC3339Nano)
	}
	g.records.write(record{
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Client:    host,
		Upstream:  up.Name,
		Ecosystem: up.Ecosystem,
		Kind:      kind,
		Package:   pkg,
		Version:   version,
		Served:    v.Served,
		Reason:    v.Reason,
		Published: published,
	})
}
