package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
		vd = verdict{false, fmt.Sprintf("the file is larger than %d bytes", maxPinnedBytes)}
	case got != f.SHA256:
		vd = verdict{false, fmt.Sprintf("its bytes hash to sha256:%s, not the pinned %s", got, digest)}
	default:
		vd = verdict{true, ""}
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
