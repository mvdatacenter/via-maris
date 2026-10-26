package main

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

var aptArchive = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Rounding down to the UTC day keeps every file of one apt update in the
// same snapshot.
func aptSnapshot(now time.Time, hold time.Duration) string {
	return now.Add(-hold).UTC().Truncate(24 * time.Hour).Format("20060102T150405Z")
}

// The archive's own signatures stand in for its publisher, so no file is
// checked further.
func (g *gateway) apt(w http.ResponseWriter, r *http.Request, up *Upstream) {
	rest := strings.TrimPrefix(r.URL.Path, "/"+up.Name+"/")
	archive, p, _ := strings.Cut(rest, "/")
	if !aptArchive.MatchString(archive) || path.Clean("/"+p) != "/"+p || !(strings.HasPrefix(p, "dists/") || strings.HasPrefix(p, "pool/")) {
		http.NotFound(w, r)
		return
	}
	snap := aptSnapshot(time.Now(), up.Hold.Duration)
	kind, pkg, ver := "metadata", p, ""
	if file := path.Base(p); strings.HasPrefix(p, "pool/") && strings.HasSuffix(file, ".deb") {
		fields := strings.Split(strings.TrimSuffix(file, ".deb"), "_")
		if len(fields) == 3 {
			kind, pkg, ver = "artifact", fields[0], fields[1]
		}
	}
	g.record(r, up, kind, pkg, ver, verdict{Served: true, Reason: "snapshot " + snap})
	g.stream(w, r, up.URL+"/"+archive+"/"+snap+"/"+(&url.URL{Path: p}).EscapedPath())
}
