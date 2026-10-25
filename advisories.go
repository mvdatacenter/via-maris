package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEntry struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string   `json:"versions"`
		Ranges   []osvRange `json:"ranges"`
	} `json:"affected"`
}

type advisory struct {
	ID        string
	Malicious bool
	Versions  map[string]bool
	Ranges    []osvRange
}

func (a *advisory) affects(eco, v string) bool {
	if a.Versions[v] {
		return true
	}
	for _, r := range a.Ranges {
		if r.Type != "GIT" && inRange(eco, r, v) {
			return true
		}
	}
	return false
}

// inRange evaluates an OSV SEMVER or ECOSYSTEM range. A version it cannot
// compare counts as affected, so an unreadable range refuses rather than serves.
func inRange(eco string, r osvRange, v string) bool {
	type point struct {
		at   string
		kind string
	}
	var pts []point
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			pts = append(pts, point{e.Introduced, "introduced"})
		case e.Fixed != "":
			pts = append(pts, point{e.Fixed, "fixed"})
		case e.LastAffected != "":
			pts = append(pts, point{e.LastAffected, "last_affected"})
		case e.Limit != "":
			pts = append(pts, point{e.Limit, "limit"})
		}
	}
	broken := false
	sort.SliceStable(pts, func(i, j int) bool {
		if pts[i].at == "0" || pts[j].at == "0" {
			return pts[i].at == "0" && pts[j].at != "0"
		}
		c, ok := compareVersions(eco, pts[i].at, pts[j].at)
		if !ok {
			broken = true
		}
		return c < 0
	})
	affected := false
	for _, p := range pts {
		if p.at == "0" {
			affected = true
			continue
		}
		c, ok := compareVersions(eco, v, p.at)
		if !ok {
			return true
		}
		switch p.kind {
		case "introduced":
			if c >= 0 {
				affected = true
			}
		case "fixed", "limit":
			if c >= 0 {
				affected = false
			}
		case "last_affected":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected || broken
}

type ecosystemData struct {
	byPackage map[string][]*advisory
	loaded    time.Time
	entries   int
	malicious int
}

type advisoryDB struct {
	source string
	client *http.Client
	mu     sync.RWMutex
	eco    map[string]*ecosystemData
}

func packageKey(eco, name string) string {
	if eco == "PyPI" {
		return normalizePyPI(name)
	}
	return name
}

func (db *advisoryDB) load(ctx context.Context, eco string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.source+"/"+eco+"/all.zip", nil)
	if err != nil {
		return err
	}
	resp, err := db.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", req.URL, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	data := &ecosystemData{byPackage: map[string][]*advisory{}}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		var e osvEntry
		err = json.NewDecoder(rc).Decode(&e)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if e.Withdrawn != "" {
			continue
		}
		data.entries++
		mal := strings.HasPrefix(e.ID, "MAL-")
		if mal {
			data.malicious++
		}
		for _, a := range e.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			adv := &advisory{ID: e.ID, Malicious: mal, Versions: map[string]bool{}, Ranges: a.Ranges}
			for _, v := range a.Versions {
				adv.Versions[v] = true
			}
			k := packageKey(eco, a.Package.Name)
			data.byPackage[k] = append(data.byPackage[k], adv)
		}
	}
	data.loaded = time.Now()
	db.mu.Lock()
	db.eco[eco] = data
	db.mu.Unlock()
	return nil
}

func (db *advisoryDB) lookup(eco, name string) []*advisory {
	db.mu.RLock()
	defer db.mu.RUnlock()
	d := db.eco[eco]
	if d == nil {
		return nil
	}
	return d.byPackage[packageKey(eco, name)]
}

func (db *advisoryDB) age(eco string) (time.Duration, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	d := db.eco[eco]
	if d == nil {
		return 0, false
	}
	return time.Since(d.loaded), true
}

func (db *advisoryDB) stats(eco string) (entries, malicious int) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if d := db.eco[eco]; d != nil {
		return d.entries, d.malicious
	}
	return 0, 0
}

func (a *advisory) fixedAt(eco, version string) []osvRange {
	var out []osvRange
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			if c, ok := compareVersions(eco, e.Fixed, version); ok && c == 0 {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// comparable reports whether v compares with every point of r. inRange counts
// a version it cannot compare as affected, which refuses; admitting a fix on
// that reading would serve on a guess, so such a version fixes nothing.
func comparable(eco string, r osvRange, v string) bool {
	for _, e := range r.Events {
		for _, at := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
			if at == "" || at == "0" {
				continue
			}
			if _, ok := compareVersions(eco, v, at); !ok {
				return false
			}
		}
	}
	return true
}
