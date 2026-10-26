package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

const indexPage = 2000

// goIndex holds the module index for the hold window: the first time the
// module proxy served each version. A version the proxy holds that is absent
// from the window was first served before the window began.
type goIndex struct {
	base   string
	client *http.Client
	hold   time.Duration
	poll   time.Duration
	maxAge time.Duration
	mu     sync.RWMutex
	seen   map[string]time.Time
	since  time.Time // the window's start
	last   time.Time // the newest timestamp read
	polled time.Time // the last poll that read the index to its head
	loaded bool      // the window has been read to the index head once
}

func newGoIndex(up *Upstream, client *http.Client) *goIndex {
	return &goIndex{
		base:   up.Index,
		client: client,
		hold:   up.Hold.Duration,
		poll:   up.IndexPoll.Duration,
		maxAge: up.IndexMaxAge.Duration,
		seen:   map[string]time.Time{},
	}
}

func (ix *goIndex) notReady() string {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	switch {
	case !ix.loaded:
		return "the Go index window has not loaded"
	case time.Since(ix.polled) > ix.maxAge:
		return fmt.Sprintf("the Go index was last read %s ago, past the %s bound", time.Since(ix.polled).Round(time.Second), ix.maxAge)
	}
	return ""
}

func (ix *goIndex) lag() time.Duration {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	if ix.last.IsZero() {
		return -time.Second
	}
	return time.Since(ix.last)
}

func (ix *goIndex) firstSeen(mod, ver string) (time.Time, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	t, ok := ix.seen[mod+"@"+ver]
	return t, ok
}

func (ix *goIndex) windowStart() time.Time {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.since
}

func (ix *goIndex) read(ctx context.Context) error {
	for {
		ix.mu.RLock()
		from := ix.last
		ix.mu.RUnlock()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/index?limit=%d&since=%s", ix.base, indexPage, url.QueryEscape(from.UTC().Format(time.RFC3339Nano))), nil)
		if err != nil {
			return err
		}
		resp, err := ix.client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("GET %s: %s", req.URL, resp.Status)
		}
		n := 0
		sc := bufio.NewScanner(resp.Body)
		ix.mu.Lock()
		for sc.Scan() {
			var e struct {
				Path, Version string
				Timestamp     time.Time
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			n++
			k := e.Path + "@" + e.Version
			if t, ok := ix.seen[k]; !ok || e.Timestamp.Before(t) {
				ix.seen[k] = e.Timestamp
			}
			if e.Timestamp.After(ix.last) {
				ix.last = e.Timestamp
			}
		}
		ix.mu.Unlock()
		err = sc.Err()
		resp.Body.Close()
		if err != nil {
			return err
		}
		if n < indexPage {
			ix.mu.Lock()
			ix.loaded = true
			ix.polled = time.Now()
			ix.mu.Unlock()
			return nil
		}
	}
}

func (ix *goIndex) begin(now time.Time) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.since = now.Add(-ix.hold - time.Hour)
	ix.last = ix.since
}

func (ix *goIndex) trim(now time.Time) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cut := now.Add(-ix.hold - time.Hour)
	for k, t := range ix.seen {
		if t.Before(cut) {
			delete(ix.seen, k)
		}
	}
	if ix.since.Before(cut) {
		ix.since = cut
	}
}

func (ix *goIndex) run(ctx context.Context, name string) {
	start := time.Now()
	ix.begin(start)
	logged := false
	every(ctx, ix.poll, func(ctx context.Context) {
		if err := ix.read(ctx); err != nil {
			log.Printf("go index %s: %v", name, err)
		} else if !logged {
			logged = true
			ix.mu.RLock()
			log.Printf("go index %s: %d versions first served since %s, loaded in %s", name, len(ix.seen), ix.since.UTC().Format(time.RFC3339), time.Since(start).Round(time.Millisecond))
			ix.mu.RUnlock()
		}
		ix.trim(time.Now())
	})
}

func unescapeModule(s string) (string, bool) {
	var b strings.Builder
	bang := false
	for _, r := range s {
		switch {
		case bang:
			if !unicode.IsLower(r) {
				return "", false
			}
			b.WriteRune(unicode.ToUpper(r))
			bang = false
		case r == '!':
			bang = true
		case unicode.IsUpper(r):
			return "", false
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), !bang
}

func escapeVersion(v string) string {
	var b strings.Builder
	for _, r := range v {
		if unicode.IsUpper(r) {
			b.WriteRune('!')
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// goMissing is the proxy's answer for a path or version it does not have.
// The go command reads 404 and 410 as "try the next path", so the gateway
// passes them on rather than refusing a module that does not exist.
type goMissing struct {
	status int
	body   []byte
}

func (e *goMissing) Error() string { return fmt.Sprintf("upstream answered %d", e.status) }

// goPublished is when the proxy first served mod@ver, or an upper bound on
// it: the window start for a version it held before the window. A version
// it has never served is first served now.
func (g *gateway) goPublished(ctx context.Context, up *Upstream, ix *goIndex, modEsc, verEsc, mod, ver string) (t time.Time, exact bool, err error) {
	if t, ok := ix.firstSeen(mod, ver); ok {
		return t, true, nil
	}
	resp, err := g.fetch(ctx, up.URL+"/cached-only/"+modEsc+"/@v/"+verEsc+".info", "")
	if err != nil {
		return time.Time{}, false, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Held by the proxy and absent from the window: read the index once
		// more, so a version first served since the last poll is not taken
		// for an old one.
		if err := ix.read(ctx); err != nil {
			return time.Time{}, false, err
		}
		if t, ok := ix.firstSeen(mod, ver); ok {
			return t, true, nil
		}
		return ix.windowStart(), false, nil
	case http.StatusNotFound, http.StatusGone:
		// Never served: ask the proxy for it, so the hold counts from now,
		// and pass on its answer when it has no such version.
		resp, err := g.fetch(ctx, up.URL+"/"+modEsc+"/@v/"+verEsc+".info", "")
		if err != nil {
			return time.Time{}, false, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return time.Now(), true, nil
		case http.StatusNotFound, http.StatusGone:
			return time.Time{}, false, &goMissing{resp.StatusCode, body}
		}
		return time.Time{}, false, fmt.Errorf("the proxy answered %s", resp.Status)
	}
	return time.Time{}, false, fmt.Errorf("cached-only answered %s", resp.Status)
}

func (g *gateway) gomod(w http.ResponseWriter, r *http.Request, up *Upstream, ix *goIndex) {
	rest := strings.TrimPrefix(r.URL.Path, "/"+up.Name+"/")
	if sub, ok := strings.CutPrefix(rest, "sumdb/"); ok {
		// The go command names the database by host alone.
		host, p, _ := strings.Cut(sub, "/")
		if db, err := url.Parse(up.SumDB); err != nil || db.Host != host {
			http.NotFound(w, r)
			return
		}
		if p == "supported" {
			w.WriteHeader(http.StatusOK)
			return
		}
		g.stream(w, r, up.SumDB+"/"+p)
		return
	}
	modEsc, tail, ok := strings.Cut(rest, "/@")
	mod, okMod := unescapeModule(modEsc)
	if !ok || !okMod || mod == "" {
		http.NotFound(w, r)
		return
	}
	if why := ix.notReady(); why != "" {
		vd := verdict{Served: false, Reason: why}
		g.record(r, up, "metadata", mod, "", vd)
		http.Error(w, refusal(mod, "*", vd), http.StatusServiceUnavailable)
		return
	}
	if why := g.advisoriesUnusable(up.Ecosystem); why != "" {
		// Advisory data that is missing or stale refuses the listings too,
		// rather than leaving them empty with no reason.
		vd := verdict{Served: false, Reason: why}
		g.record(r, up, "metadata", mod, "", vd)
		http.Error(w, refusal(mod, "*", vd), http.StatusServiceUnavailable)
		return
	}
	switch {
	case tail == "v/list":
		g.goList(w, r, up, ix, modEsc, mod)
	case tail == "latest":
		g.goLatest(w, r, up, ix, modEsc, mod)
	case strings.HasPrefix(tail, "v/"):
		file := strings.TrimPrefix(tail, "v/")
		var verEsc string
		for _, ext := range []string{".info", ".mod", ".zip"} {
			if strings.HasSuffix(file, ext) {
				verEsc = strings.TrimSuffix(file, ext)
			}
		}
		ver, okVer := unescapeModule(verEsc)
		if verEsc == "" || !okVer {
			http.NotFound(w, r)
			return
		}
		vd, missing := g.goCheck(r.Context(), up, ix, modEsc, verEsc, mod, ver)
		if missing != nil {
			g.record(r, up, "missing", mod, ver, vd)
			w.WriteHeader(missing.status)
			w.Write(missing.body)
			return
		}
		g.record(r, up, "artifact", mod, ver, vd)
		if !vd.Served {
			refuse(w, refusal(mod, ver, vd), false)
			return
		}
		g.stream(w, r, up.URL+"/"+modEsc+"/@v/"+file)
	default:
		http.NotFound(w, r)
	}
}

func (g *gateway) goCheck(ctx context.Context, up *Upstream, ix *goIndex, modEsc, verEsc, mod, ver string) (verdict, *goMissing) {
	if vd, ok := g.advisoryRefusal(up, mod, ver); !ok {
		// The window alone is read: asking the proxy would have it fetch the
		// refused version.
		vd.Published, _ = ix.firstSeen(mod, ver)
		return vd, nil
	}
	t, exact, err := g.goPublished(ctx, up, ix, modEsc, verEsc, mod, ver)
	var missing *goMissing
	if errors.As(err, &missing) {
		return verdict{Served: false, Reason: "the upstream has no such version"}, missing
	}
	if err != nil {
		return verdict{Served: false, Reason: "the first-served time could not be read: " + err.Error()}, nil
	}
	vd := g.check(up, mod, ver, t)
	if !exact {
		vd.Published = time.Time{}
	}
	return vd, nil
}

// goList serves the version list without the refused versions, dating each
// from the window. A listed version absent from the window is dated as
// served before it; were it one the proxy has never served, its .info is
// still refused when the go command asks for it.
func (g *gateway) goList(w http.ResponseWriter, r *http.Request, up *Upstream, ix *goIndex, modEsc, mod string) {
	resp, err := g.fetch(r.Context(), up.URL+"/"+modEsc+"/@v/list", "")
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		upstreamError(w, err)
		return
	}
	var kept []string
	total := 0
	for _, v := range strings.Fields(string(body)) {
		total++
		t, ok := ix.firstSeen(mod, v)
		if !ok {
			t = ix.windowStart()
		}
		if g.check(up, mod, v, t).Served {
			kept = append(kept, v)
		}
	}
	g.record(r, up, "metadata", mod, "", verdict{Served: true, Reason: fmt.Sprintf("%d of %d versions refused", total-len(kept), total)})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, v := range kept {
		fmt.Fprintln(w, v)
	}
}

func (g *gateway) goLatest(w http.ResponseWriter, r *http.Request, up *Upstream, ix *goIndex, modEsc, mod string) {
	resp, err := g.fetch(r.Context(), up.URL+"/"+modEsc+"/@latest", "")
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		upstreamError(w, err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}
	var info struct{ Version string }
	if err := json.Unmarshal(body, &info); err != nil || info.Version == "" {
		vd := verdict{Served: false, Reason: "the upstream's latest answer names no version"}
		g.record(r, up, "metadata", mod, "", vd)
		refuse(w, refusal(mod, "latest", vd), false)
		return
	}
	vd, missing := g.goCheck(r.Context(), up, ix, modEsc, escapeVersion(info.Version), mod, info.Version)
	if missing != nil {
		g.record(r, up, "missing", mod, info.Version, vd)
		w.WriteHeader(missing.status)
		w.Write(missing.body)
		return
	}
	g.record(r, up, "metadata", mod, info.Version, vd)
	if !vd.Served {
		refuse(w, refusal(mod, info.Version, vd), false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
