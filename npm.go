package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// npmPassthrough are the registry endpoints forwarded as they are: the audit
// and ping endpoints, which carry no package bytes.
var npmPassthrough = []string{"-/npm/v1/security/", "-/ping"}

func (g *gateway) npm(w http.ResponseWriter, r *http.Request, up *Upstream) {
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/"+up.Name+"/")
	g.npmPath(w, r, up, rest, func(name, tb string) string {
		return baseURL(r) + "/" + up.Name + "/" + name + "/-/" + path.Base(tb)
	})
}

func (g *gateway) npmPath(w http.ResponseWriter, r *http.Request, up *Upstream, rest string, tarballURL func(name, tb string) string) {
	if strings.HasPrefix(rest, "-/") {
		for _, p := range npmPassthrough {
			if strings.HasPrefix(rest, p) {
				g.npmForward(w, r, up, rest)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		http.Error(w, "via-maris: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest, err := url.PathUnescape(rest)
	if err != nil {
		http.Error(w, "via-maris: bad path", http.StatusBadRequest)
		return
	}
	parts := strings.Split(rest, "/")
	name, tail := parts[0], parts[1:]
	if strings.HasPrefix(name, "@") {
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		name, tail = parts[0]+"/"+parts[1], parts[2:]
	}
	switch {
	case name == "" || name == "@/" || strings.Contains(name, ".."):
		http.NotFound(w, r)
	case len(tail) == 0:
		g.npmPackument(w, r, up, name, tarballURL)
	case len(tail) == 2 && tail[0] == "-":
		g.npmTarball(w, r, up, name, tail[1])
	default:
		http.NotFound(w, r)
	}
}

func (g *gateway) npmForward(w http.ResponseWriter, r *http.Request, up *Upstream, rest string) {
	target := up.URL + "/" + rest
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, h := range []string{"Content-Type", "Content-Encoding", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	resp, err := g.client.Do(req)
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// packument fetches a package's full document, which alone carries the
// publication times the check needs.
func (g *gateway) packument(ctx context.Context, up *Upstream, name string) (map[string]any, int, error) {
	resp, err := g.fetch(ctx, up.URL+"/"+url.PathEscape(name), "application/json")
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var doc map[string]any
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", name, err)
	}
	return doc, http.StatusOK, nil
}

func npmPublished(doc map[string]any, version string) time.Time {
	times, _ := doc["time"].(map[string]any)
	s, _ := times[version].(string)
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// npmPackument serves the packument with every refused version marked
// deprecated by its reason, so a range resolves to a version that is served
// and an exact pin fails at its tarball naming why. Each tarball URL is the
// one tarballURL gives.
func (g *gateway) npmPackument(w http.ResponseWriter, r *http.Request, up *Upstream, name string, tarballURL func(name, tb string) string) {
	doc, status, err := g.packument(r.Context(), up, name)
	if err != nil {
		upstreamError(w, err)
		return
	}
	if status != http.StatusOK {
		upstreamStatus(w, status, name)
		return
	}
	versions, _ := doc["versions"].(map[string]any)
	refused := map[string]bool{}
	var allowed []string
	for v, m := range versions {
		man, _ := m.(map[string]any)
		if man == nil {
			continue
		}
		if dist, ok := man["dist"].(map[string]any); ok {
			if tb, ok := dist["tarball"].(string); ok {
				dist["tarball"] = tarballURL(name, tb)
			}
		}
		vd := g.check(up, name, v, npmPublished(doc, v))
		if !vd.Served {
			man["deprecated"] = refusal(name, v, vd)
			refused[v] = true
			continue
		}
		allowed = append(allowed, v)
	}
	if tags, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, tv := range tags {
			if s, _ := tv.(string); refused[s] {
				if best := highestSemverBelow(allowed, s, tag == "latest"); best != "" {
					tags[tag] = best
				} else {
					delete(tags, tag)
				}
			}
		}
	}
	g.record(r, up, "metadata", name, "", verdict{Served: true, Reason: fmt.Sprintf("%d of %d versions refused", len(refused), len(versions))})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// highestSemverBelow is the newest of vs below ceiling, the version a refused
// tag named, so a tag such as latest-1.x never moves past its own line.
func highestSemverBelow(vs []string, ceiling string, releaseOnly bool) string {
	top, topOK := parseSemver(ceiling)
	best, bestV := "", semver{}
	for _, v := range vs {
		sv, ok := parseSemver(v)
		if !ok || (releaseOnly && len(sv.pre) > 0) || (topOK && compareSemver(sv, top) >= 0) {
			continue
		}
		if best == "" || compareSemver(sv, bestV) > 0 {
			best, bestV = v, sv
		}
	}
	return best
}

// npmTarball serves a tarball only for a version the packument lists, after
// checking that version. A lockfile names the tarball directly, so this is
// where a pinned install is refused.
func (g *gateway) npmTarball(w http.ResponseWriter, r *http.Request, up *Upstream, name, file string) {
	doc, status, err := g.packument(r.Context(), up, name)
	if err != nil {
		upstreamError(w, err)
		return
	}
	if status != http.StatusOK {
		upstreamStatus(w, status, name)
		return
	}
	versions, _ := doc["versions"].(map[string]any)
	for v, m := range versions {
		man, _ := m.(map[string]any)
		dist, _ := man["dist"].(map[string]any)
		tb, _ := dist["tarball"].(string)
		if tb == "" || path.Base(tb) != file {
			continue
		}
		vd := g.check(up, name, v, npmPublished(doc, v))
		g.record(r, up, "artifact", name, v, vd)
		if !vd.Served {
			refuse(w, refusal(name, v, vd), true)
			return
		}
		g.stream(w, r, tb)
		return
	}
	vd := verdict{Served: false, Reason: "no version of the package lists this tarball"}
	g.record(r, up, "artifact", name, file, vd)
	refuse(w, refusal(name, file, vd), true)
}
