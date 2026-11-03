package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxPinnedBytes bounds a pinned file, which is held in memory until its
// digest is known.
const maxPinnedBytes = 1 << 30

// The whole file is read before any byte is sent, so a file whose digest does
// not match never reaches the client.
func (g *gateway) pinned(w http.ResponseWriter, r *http.Request, up *Upstream) {
	name := strings.TrimPrefix(r.URL.Path, "/"+up.Name+"/")
	var f *PinnedFile
	for i := range up.Pinned {
		if up.Pinned[i].Name == name {
			f = &up.Pinned[i]
		}
	}
	if f == nil {
		http.NotFound(w, r)
		return
	}
	if h := g.held[up.Name]; h != nil {
		h.serve(w, r, f)
		return
	}
	digest := "sha256:" + f.SHA256
	resp, err := g.fetch(r.Context(), f.URL, "")
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		upstreamStatus(w, resp.StatusCode, name)
		return
	}
	var body bytes.Buffer
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(&body, sum), io.LimitReader(resp.Body, maxPinnedBytes+1))
	if err != nil {
		upstreamError(w, err)
		return
	}
	var vd verdict
	switch got := hex.EncodeToString(sum.Sum(nil)); {
	case n > maxPinnedBytes:
		vd = verdict{Served: false, Reason: fmt.Sprintf("the file is larger than %d bytes", maxPinnedBytes)}
	case got != f.SHA256:
		vd = verdict{Served: false, Reason: fmt.Sprintf("its bytes hash to sha256:%s, not the pinned %s", got, digest)}
	default:
		vd = verdict{Served: true}
	}
	g.record(r, up, "artifact", name, digest, vd)
	if !vd.Served {
		refuse(w, fmt.Sprintf("via-maris refused %s: %s", name, vd.Reason), false)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Write(body.Bytes())
}

var heldRetry = time.Minute

const heldFetchTimeout = 15 * time.Minute

// heldFiles is the held directory docs/configuration.md describes under
// "Maven and pinned files by their own names". A file fetched on request
// reaches the client only after its last byte, which for a Gradle
// distribution comes after the networkTimeout=10000 that
// testdata/gradle/gradle/wrapper/gradle-wrapper.properties sets.
type heldFiles struct {
	g   *gateway
	up  *Upstream
	dir string

	mu      sync.Mutex
	held    map[string]bool   // by digest
	lastErr map[string]string // by digest
}

func newHeldFiles(g *gateway, up *Upstream) *heldFiles {
	return &heldFiles{g: g, up: up, dir: up.Held, held: map[string]bool{}, lastErr: map[string]string{}}
}

func (h *heldFiles) path(f *PinnedFile) string { return filepath.Join(h.dir, f.SHA256) }

func (h *heldFiles) unheld() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	seen := map[string]bool{}
	for _, f := range h.up.Pinned {
		if !h.held[f.SHA256] && !seen[f.SHA256] {
			n++
		}
		seen[f.SHA256] = true
	}
	return n
}

func (h *heldFiles) isHeld(f *PinnedFile) (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.held[f.SHA256], h.lastErr[f.SHA256]
}

func (h *heldFiles) run(ctx context.Context) {
	if err := os.MkdirAll(h.dir, 0o755); err != nil {
		log.Printf("held files %s: %v", h.up.Name, err)
	}
	for {
		h.fetchMissing(ctx)
		if h.unheld() == 0 {
			h.prune()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(heldRetry):
		}
	}
}

func (h *heldFiles) fetchMissing(ctx context.Context) {
	for i := range h.up.Pinned {
		f := &h.up.Pinned[i]
		if ok, _ := h.isHeld(f); ok {
			continue
		}
		err := h.verifyHeld(f)
		if err != nil {
			fctx, cancel := context.WithTimeout(ctx, heldFetchTimeout)
			start := time.Now()
			err = h.fetch(fctx, f)
			cancel()
			if err == nil {
				log.Printf("held files %s: fetched %s in %s", h.up.Name, f.Name, time.Since(start).Round(time.Millisecond))
			}
		}
		h.mu.Lock()
		if err != nil {
			h.lastErr[f.SHA256] = err.Error()
			log.Printf("held files %s: %s: %v; retrying in %s", h.up.Name, f.Name, err, heldRetry)
		} else {
			h.held[f.SHA256] = true
			delete(h.lastErr, f.SHA256)
		}
		h.mu.Unlock()
	}
}

func (h *heldFiles) verifyHeld(f *PinnedFile) error {
	file, err := os.Open(h.path(f))
	if err != nil {
		return err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("the held copy hashes to sha256:%s", got)
	}
	return nil
}

func (h *heldFiles) fetch(ctx context.Context, f *PinnedFile) error {
	resp, err := h.g.fetch(ctx, f.URL, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: upstream answered %s", f.URL, resp.Status)
	}
	tmp, err := os.CreateTemp(h.dir, ".fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, maxPinnedBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch got := hex.EncodeToString(sum.Sum(nil)); {
	case err != nil:
		return err
	case n > maxPinnedBytes:
		return fmt.Errorf("the file is larger than %d bytes", maxPinnedBytes)
	case got != f.SHA256:
		return fmt.Errorf("its bytes hash to sha256:%s, not the pinned sha256:%s", got, f.SHA256)
	}
	return os.Rename(tmp.Name(), h.path(f))
}

func (h *heldFiles) prune() {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return
	}
	pinned := map[string]bool{}
	for _, f := range h.up.Pinned {
		pinned[f.SHA256] = true
	}
	for _, e := range entries {
		if !pinned[e.Name()] && !strings.HasPrefix(e.Name(), ".fetch-") {
			if err := os.Remove(filepath.Join(h.dir, e.Name())); err == nil {
				log.Printf("held files %s: removed %s, which is no longer pinned", h.up.Name, e.Name())
			}
		}
	}
}

func (h *heldFiles) serve(w http.ResponseWriter, r *http.Request, f *PinnedFile) {
	digest := "sha256:" + f.SHA256
	ok, lastErr := h.isHeld(f)
	var file *os.File
	if ok {
		var err error
		if file, err = os.Open(h.path(f)); err != nil {
			ok, lastErr = false, err.Error()
			h.mu.Lock()
			delete(h.held, f.SHA256)
			h.lastErr[f.SHA256] = lastErr
			h.mu.Unlock()
		}
	}
	if !ok {
		reason := "it is not held yet, and its first fetch has not finished"
		if lastErr != "" {
			reason = "it is not held yet; its last fetch failed: " + lastErr
		}
		h.g.record(r, h.up, "artifact", f.Name, digest, verdict{Served: false, Reason: reason})
		refuseInStatus(w, r, fmt.Sprintf("via-maris refused %s: %s", f.Name, reason))
		return
	}
	defer file.Close()
	h.g.record(r, h.up, "artifact", f.Name, digest, verdict{Served: true})
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", time.Time{}, file)
}
