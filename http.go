package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	resp, err := g.fetch(r.Context(), url, r.Header.Get("Accept"))
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Content-Length", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
