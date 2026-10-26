package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"path"
	"strings"
	"time"
)

const simpleJSON = "application/vnd.pypi.simple.v1+json"

func (g *gateway) pypi(w http.ResponseWriter, r *http.Request, up *Upstream) {
	rest := strings.TrimPrefix(r.URL.Path, "/"+up.Name+"/")
	switch {
	case strings.HasPrefix(rest, "simple/"):
		project := strings.Trim(strings.TrimPrefix(rest, "simple/"), "/")
		if project == "" || strings.Contains(project, "/") || strings.Contains(project, "..") {
			http.NotFound(w, r)
			return
		}
		g.pypiSimple(w, r, up, normalizePyPI(project), func(rel string) string { return baseURL(r) + "/" + up.Name + "/files/" + rel })
	case strings.HasPrefix(rest, "files/"):
		g.pypiFile(w, r, up, strings.TrimPrefix(rest, "files/"))
	default:
		http.NotFound(w, r)
	}
}

func (g *gateway) simplePage(ctx context.Context, up *Upstream, project string) (map[string]any, int, error) {
	resp, err := g.fetch(ctx, up.URL+"/simple/"+project+"/", simpleJSON)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", project, err)
	}
	return doc, http.StatusOK, nil
}

var sdistSuffixes = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"}

func pypiFilename(filename string) (project, version string, ok bool) {
	if stem, isWheel := strings.CutSuffix(filename, ".whl"); isWheel {
		parts := strings.Split(stem, "-")
		if len(parts) < 5 {
			return "", "", false
		}
		return normalizePyPI(parts[0]), parts[1], true
	}
	for _, ext := range sdistSuffixes {
		if stem, isSdist := strings.CutSuffix(filename, ext); isSdist {
			i := strings.LastIndex(stem, "-")
			if i <= 0 || i == len(stem)-1 {
				return "", "", false
			}
			return normalizePyPI(stem[:i]), stem[i+1:], true
		}
	}
	return "", "", false
}

func fileField(f map[string]any, k string) string {
	s, _ := f[k].(string)
	return s
}

func (g *gateway) pypiFileVerdict(up *Upstream, project, filename, uploaded string) (string, verdict) {
	p, v, ok := pypiFilename(filename)
	if !ok || p != project {
		return filename, verdict{Served: false, Reason: "the filename carries no version of this project"}
	}
	t, _ := time.Parse(time.RFC3339, uploaded)
	return v, g.check(up, project, v, t)
}

// pypiSimple serves a project page whose refused files are yanked with their
// reason, so a range skips them and an exact pin names why, and whose file
// URLs are the ones fileURL gives for each path under the files host. A file
// the upstream lists on a host other than its configured files host is left
// out, because the gateway cannot serve it.
func (g *gateway) pypiSimple(w http.ResponseWriter, r *http.Request, up *Upstream, project string, fileURL func(rel string) string) {
	doc, status, err := g.simplePage(r.Context(), up, project)
	if err != nil {
		upstreamError(w, err)
		return
	}
	if status != http.StatusOK {
		upstreamStatus(w, status, project)
		return
	}
	listed, _ := doc["files"].([]any)
	var files []any
	refused := 0
	for _, x := range listed {
		f, _ := x.(map[string]any)
		if f == nil {
			continue
		}
		rel, ok := strings.CutPrefix(fileField(f, "url"), up.Files+"/")
		if !ok {
			continue
		}
		f["url"] = fileURL(rel)
		v, vd := g.pypiFileVerdict(up, project, fileField(f, "filename"), fileField(f, "upload-time"))
		if !vd.Served {
			f["yanked"] = refusal(project, v, vd)
			refused++
		}
		files = append(files, f)
	}
	doc["files"] = files
	g.record(r, up, "metadata", project, "", verdict{Served: true, Reason: fmt.Sprintf("%d of %d files refused", refused, len(listed))})
	if strings.Contains(r.Header.Get("Accept"), simpleJSON) {
		w.Header().Set("Content-Type", simpleJSON)
		json.NewEncoder(w).Encode(doc)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!DOCTYPE html>\n<html><body>\n")
	for _, x := range files {
		f := x.(map[string]any)
		href := fileField(f, "url")
		if h, ok := f["hashes"].(map[string]any); ok {
			if s, ok := h["sha256"].(string); ok {
				href += "#sha256=" + s
			}
		}
		attrs := ""
		if rp := fileField(f, "requires-python"); rp != "" {
			attrs += fmt.Sprintf(` data-requires-python="%s"`, html.EscapeString(rp))
		}
		if h, ok := f["core-metadata"].(map[string]any); ok {
			if s, ok := h["sha256"].(string); ok {
				attrs += fmt.Sprintf(` data-core-metadata="sha256=%s"`, html.EscapeString(s))
			}
		}
		switch y := f["yanked"].(type) {
		case string:
			attrs += fmt.Sprintf(` data-yanked="%s"`, html.EscapeString(y))
		case bool:
			if y {
				attrs += ` data-yanked=""`
			}
		}
		fmt.Fprintf(w, "<a href=\"%s\"%s>%s</a><br/>\n", html.EscapeString(href), attrs, html.EscapeString(fileField(f, "filename")))
	}
	fmt.Fprintf(w, "</body></html>\n")
}

func (g *gateway) pypiFile(w http.ResponseWriter, r *http.Request, up *Upstream, rel string) {
	listed := strings.TrimSuffix(rel, ".metadata")
	filename := path.Base(listed)
	project, _, ok := pypiFilename(filename)
	if ok && !strings.Contains(listed, "..") {
		// A project the upstream does not answer for lists nothing.
		doc, _, err := g.simplePage(r.Context(), up, project)
		if err != nil {
			upstreamError(w, err)
			return
		}
		files, _ := doc["files"].([]any)
		for _, x := range files {
			f, _ := x.(map[string]any)
			if f == nil || fileField(f, "url") != up.Files+"/"+listed {
				continue
			}
			v, vd := g.pypiFileVerdict(up, project, fileField(f, "filename"), fileField(f, "upload-time"))
			if rel != listed && !vd.Served {
				// Core metadata is text, never run. Serving it lets uv finish
				// resolving an exact pin and print the yanked reason before
				// the file itself is refused.
				g.record(r, up, "metadata", project, v, verdict{Served: true, Reason: "core metadata of a refused file: " + vd.Reason, Published: vd.Published})
				g.stream(w, r, up.Files+"/"+rel)
				return
			}
			g.record(r, up, "artifact", project, v, vd)
			if !vd.Served {
				refuseInStatus(w, r, refusal(project, v, vd))
				return
			}
			g.stream(w, r, up.Files+"/"+rel)
			return
		}
	}
	vd := verdict{Served: false, Reason: "no project index lists this file"}
	g.record(r, up, "artifact", project, filename, vd)
	refuseInStatus(w, r, refusal(project, filename, vd))
}
