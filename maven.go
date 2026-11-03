package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

var mavenChecksums = map[string]func() hash.Hash{
	".md5": md5.New, ".sha1": sha1.New, ".sha256": sha256.New, ".sha512": sha512.New,
}

var mavenSegment = regexp.MustCompile(`^[A-Za-z0-9_+~-][A-Za-z0-9._+~-]*$`)

type mavenRef struct {
	dir      string // the artifact's directory, group directories then artifact
	group    string
	artifact string
	version  string // empty for metadata
	file     string
	checksum string // the checksum extension of a metadata checksum file
}

func (m mavenRef) pkg() string { return m.group + ":" + m.artifact }

func parseMavenRef(rel string) (mavenRef, bool) {
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if !mavenSegment.MatchString(p) {
			return mavenRef{}, false
		}
	}
	n := len(parts)
	last := parts[n-1]
	if rest, ok := strings.CutPrefix(last, "maven-metadata.xml"); ok && (rest == "" || mavenChecksums[rest] != nil) {
		if n < 3 {
			return mavenRef{}, false
		}
		return mavenRef{
			dir: strings.Join(parts[:n-1], "/"), group: strings.Join(parts[:n-2], "."),
			artifact: parts[n-2], file: last, checksum: rest,
		}, true
	}
	if n < 4 {
		return mavenRef{}, false
	}
	return mavenRef{
		dir: strings.Join(parts[:n-2], "/"), group: strings.Join(parts[:n-3], "."),
		artifact: parts[n-3], version: parts[n-2], file: last,
	}, true
}

// A .pom's Last-Modified is kept for good: a repository sets it when it
// stores a release, and a released version cannot be deployed again.
type pomDates struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (g *gateway) pomPublished(ctx context.Context, up *Upstream, ref mavenRef, v string) (time.Time, int, error) {
	u := fmt.Sprintf("%s/%s/%s/%s-%s.pom", up.URL, ref.dir, v, ref.artifact, v)
	g.poms.mu.Lock()
	t, ok := g.poms.at[u]
	g.poms.mu.Unlock()
	if ok {
		return t, http.StatusOK, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("User-Agent", "via-maris/"+version)
	resp, err := g.client.Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return time.Time{}, resp.StatusCode, nil
	default:
		return time.Time{}, 0, fmt.Errorf("HEAD %s: %s", u, resp.Status)
	}
	t, err = http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		// Refused at the check as giving no publication time, and asked
		// again next time rather than held.
		return time.Time{}, http.StatusOK, nil
	}
	g.poms.mu.Lock()
	g.poms.at[u] = t
	g.poms.mu.Unlock()
	return t, http.StatusOK, nil
}

// An advisory is checked before the .pom is read, so a version the upstream
// has since removed is still refused by name.
func (g *gateway) mavenVerdict(ctx context.Context, up *Upstream, ref mavenRef, version string) (verdict, int, error) {
	if vd, ok := g.advisoryRefusal(up, ref.pkg(), version); !ok {
		return vd, http.StatusOK, nil
	}
	published, status, err := g.pomPublished(ctx, up, ref, version)
	if err != nil || status != http.StatusOK {
		return verdict{}, status, err
	}
	return g.check(up, ref.pkg(), version, published), http.StatusOK, nil
}

func (g *gateway) maven(w http.ResponseWriter, r *http.Request, up *Upstream) {
	g.mavenPath(w, r, up, strings.TrimPrefix(r.URL.Path, "/"+up.Name+"/"))
}

func (g *gateway) mavenPath(w http.ResponseWriter, r *http.Request, up *Upstream, rel string) {
	ref, ok := parseMavenRef(rel)
	switch {
	case !ok:
		vd := verdict{Served: false, Reason: "the path is neither a version's file nor an artifact's maven-metadata.xml"}
		g.record(r, up, "artifact", rel, "", vd)
		refuseInStatus(w, r, fmt.Sprintf("via-maris refused %s: %s", rel, vd.Reason))
	case ref.version == "":
		g.mavenMetadata(w, r, up, ref)
	case !strings.HasPrefix(ref.file, ref.artifact+"-"+ref.version):
		vd := verdict{Served: false, Reason: fmt.Sprintf("its file name does not start with %s-%s", ref.artifact, ref.version)}
		g.record(r, up, "artifact", ref.pkg(), ref.version, vd)
		refuseInStatus(w, r, fmt.Sprintf("via-maris refused %s: %s", rel, vd.Reason))
	default:
		vd, status, err := g.mavenVerdict(r.Context(), up, ref, ref.version)
		if err != nil {
			upstreamError(w, err)
			return
		}
		if status != http.StatusOK {
			upstreamStatus(w, status, ref.pkg()+"@"+ref.version)
			return
		}
		g.record(r, up, "artifact", ref.pkg(), ref.version, vd)
		if !vd.Served {
			refuseInStatus(w, r, refusal(ref.pkg(), ref.version, vd))
			return
		}
		g.stream(w, r, up.URL+"/"+rel)
	}
}

const maxMetadataBytes = 16 << 20

const mavenDating = 16

func (g *gateway) mavenMetadata(w http.ResponseWriter, r *http.Request, up *Upstream, ref mavenRef) {
	resp, err := g.fetch(r.Context(), up.URL+"/"+ref.dir+"/maven-metadata.xml", "")
	if err != nil {
		upstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		upstreamStatus(w, resp.StatusCode, ref.pkg())
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		upstreamError(w, err)
		return
	}
	if len(body) > maxMetadataBytes {
		upstreamError(w, fmt.Errorf("%s: maven-metadata.xml is larger than %d bytes", ref.pkg(), maxMetadataBytes))
		return
	}
	versions := mavenListed(string(body))
	served := make([]bool, len(versions))
	errs := make([]error, len(versions))
	sem := make(chan struct{}, mavenDating)
	var wg sync.WaitGroup
	for i, v := range versions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vd, status, err := g.mavenVerdict(r.Context(), up, ref, v)
			switch {
			case err != nil:
				errs[i] = err
			case status == http.StatusOK:
				served[i] = vd.Served
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			upstreamError(w, fmt.Errorf("%s: %w", ref.pkg(), err))
			return
		}
	}
	var allowed []string
	refused := map[string]bool{}
	for i, v := range versions {
		if served[i] {
			allowed = append(allowed, v)
		} else {
			refused[v] = true
		}
	}
	out := []byte(rewriteMavenMetadata(string(body), refused, allowed))
	g.record(r, up, "metadata", ref.pkg(), "", verdict{Served: true, Reason: fmt.Sprintf("%d of %d versions refused", len(refused), len(versions))})
	if ref.checksum != "" {
		h := mavenChecksums[ref.checksum]()
		h.Write(out)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Write(out)
}

var (
	mavenVersionsBlock = regexp.MustCompile(`(?s)<versions>.*?</versions>`)
	mavenVersionLine   = regexp.MustCompile(`[ \t]*<version>\s*([^<]*?)\s*</version>[ \t]*(\r?\n)?`)
)

func mavenListed(doc string) []string {
	var out []string
	for _, m := range mavenVersionLine.FindAllStringSubmatch(mavenVersionsBlock.FindString(doc), -1) {
		out = append(out, m[1])
	}
	return out
}

func rewriteMavenMetadata(doc string, refused map[string]bool, allowed []string) string {
	doc = mavenVersionsBlock.ReplaceAllStringFunc(doc, func(block string) string {
		return mavenVersionLine.ReplaceAllStringFunc(block, func(line string) string {
			if refused[mavenVersionLine.FindStringSubmatch(line)[1]] {
				return ""
			}
			return line
		})
	})
	newest := func(release bool) string {
		best := ""
		for _, v := range allowed {
			if release && strings.HasSuffix(v, "-SNAPSHOT") {
				continue
			}
			if c, _ := compareVersions("Maven", v, best); best == "" || c > 0 {
				best = v
			}
		}
		return best
	}
	for _, tag := range []string{"latest", "release"} {
		re := regexp.MustCompile(`[ \t]*<` + tag + `>\s*([^<]*?)\s*</` + tag + `>[ \t]*(\r?\n)?`)
		doc = re.ReplaceAllStringFunc(doc, func(el string) string {
			if !refused[re.FindStringSubmatch(el)[1]] {
				return el
			}
			v := newest(tag == "release")
			if v == "" {
				return ""
			}
			return regexp.MustCompile(`>[^<]*<`).ReplaceAllString(el, ">"+v+"<")
		})
	}
	return doc
}

// mavenByName is the front end "Maven and pinned files by their own names"
// in docs/configuration.md describes.
type mavenByName struct {
	repos    []mavenRepo
	listings []mavenListing
	files    *Upstream
	held     *heldFiles
	hosts    []string
	certs    *certFiles
	recordAs *Upstream
	h        http.HandlerFunc
}

type mavenRepo struct {
	root mavenRoot
	up   *Upstream
}

type mavenListing struct {
	root mavenRoot
	url  string
}

func newMavenByName(g *gateway, cfg *MavenByName) *mavenByName {
	m := &mavenByName{
		hosts: cfg.hosts(g.cfg),
		certs: &certFiles{cert: cfg.Cert, key: cfg.Key, ca: cfg.CA},
	}
	for _, name := range cfg.Upstreams {
		up := upstreamNamed(g, name)
		root, _ := splitRoot(up.URL)
		m.repos = append(m.repos, mavenRepo{root, up})
	}
	for _, l := range cfg.Listings {
		root, _ := splitRoot(l)
		m.listings = append(m.listings, mavenListing{root, l})
	}
	// A request on a Maven name that reaches no repository is recorded under
	// the files upstream, or under the first repository when there is none.
	m.recordAs = m.repos[0].up
	if cfg.Files != "" {
		m.files = upstreamNamed(g, cfg.Files)
		m.held = g.held[cfg.Files]
		m.recordAs = m.files
	}
	m.h = g.gated(m.recordAs, func(w http.ResponseWriter, r *http.Request) { g.mavenByName(w, r, m) })
	return m
}

func (m *mavenByName) serves(host string) bool {
	for _, h := range m.hosts {
		if h == host {
			return true
		}
	}
	return false
}

func (g *gateway) mavenByName(w http.ResponseWriter, r *http.Request, m *mavenByName) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	p := r.URL.EscapedPath()
	for _, repo := range m.repos {
		if rel, ok := strings.CutPrefix(p, repo.root.path+"/"); ok && host == repo.root.host {
			g.mavenPath(w, r, repo.up, rel)
			return
		}
	}
	if m.files != nil {
		for i := range m.files.Pinned {
			f := &m.files.Pinned[i]
			if root, _ := splitRoot(f.URL); root.host == host && root.path == p {
				m.held.serve(w, r, f)
				return
			}
		}
	}
	where := "https://" + host + p
	for _, l := range m.listings {
		rest, ok := strings.CutPrefix(p, l.root.path+"/")
		if ok && host == l.root.host && strings.HasSuffix(rest, ".xml") && !slices.ContainsFunc(strings.Split(rest, "/"), func(s string) bool { return s == "" || s == "." || s == ".." }) {
			g.record(r, m.recordAs, "metadata", where, "", verdict{Served: true, Reason: "a listing, served as fetched"})
			g.stream(w, r, l.url+"/"+rest)
			return
		}
	}
	vd := verdict{Served: false, Reason: "it is not a pinned file, a path in a Maven repository, or a listing"}
	g.record(r, m.recordAs, "artifact", where, "", vd)
	refuseInStatus(w, r, fmt.Sprintf("via-maris refused %s: %s", where, vd.Reason))
}
