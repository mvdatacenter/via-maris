package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type RecheckConfig struct {
	Advisories struct {
		Source string `json:"source"`
	} `json:"advisories"`
	Ecosystems []string `json:"ecosystems"`
	GitHub     struct {
		API               string `json:"api"`
		Owner             string `json:"owner"`
		AppIDEnv          string `json:"appIdEnv"`
		InstallationIDEnv string `json:"installationIdEnv"`
		PrivateKeyEnv     string `json:"privateKeyEnv"`
	} `json:"github"`
	OSVScanner   string   `json:"osvScanner"`
	WorkDir      string   `json:"workDir"`
	Alertmanager string   `json:"alertmanager"`
	AlertFor     Duration `json:"alertFor"`
	InUse        struct {
		Store  Store  `json:"store"`
		Object string `json:"object"`
	} `json:"inUse"`
	Records struct {
		Store   Store    `json:"store"`
		Prefix  string   `json:"prefix"`
		Overlap Duration `json:"overlap"`
	} `json:"records"`
	ServedWindow Duration `json:"servedWindow"`
}

func loadRecheckConfig(path string) (*RecheckConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c RecheckConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *RecheckConfig) validate() error {
	if !httpURL(c.Advisories.Source) {
		return errors.New("advisories.source must be an http(s) URL without a trailing slash")
	}
	if len(c.Ecosystems) == 0 {
		return errors.New("ecosystems is empty")
	}
	for _, eco := range c.Ecosystems {
		if !(&Upstream{Ecosystem: eco}).checked() {
			return fmt.Errorf("ecosystem %q is not npm, PyPI or Go", eco)
		}
	}
	gh := c.GitHub
	if !httpURL(gh.API) || gh.Owner == "" {
		return errors.New("github needs an http(s) api URL without a trailing slash, and an owner")
	}
	for _, env := range []string{gh.AppIDEnv, gh.InstallationIDEnv, gh.PrivateKeyEnv} {
		if env == "" || os.Getenv(env) == "" {
			return errors.New("github: appIdEnv, installationIdEnv and privateKeyEnv must name environment variables that are set")
		}
	}
	if !filepath.IsAbs(c.OSVScanner) || !filepath.IsAbs(c.WorkDir) {
		return errors.New("osvScanner and workDir must be absolute paths")
	}
	if !httpURL(c.Alertmanager) || c.AlertFor.Duration <= 0 {
		return errors.New("alertmanager must be an http(s) URL without a trailing slash, and alertFor positive")
	}
	if err := c.InUse.Store.validate("inUse"); err != nil {
		return err
	}
	if c.InUse.Object == "" {
		return errors.New("inUse.object is required")
	}
	if err := c.Records.Store.validate("records"); err != nil {
		return err
	}
	if c.Records.Overlap.Duration <= 0 || c.ServedWindow.Duration <= c.Records.Overlap.Duration {
		return errors.New("servedWindow must exceed a positive records.overlap")
	}
	return nil
}

type lockedPackage struct {
	Repository string
	Lockfile   string
	Ecosystem  string
	Name       string
	Version    string
}

type osvScan struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		} `json:"packages"`
	} `json:"results"`
}

func parseScan(out []byte, root string) ([]lockedPackage, error) {
	var scan osvScan
	if err := json.Unmarshal(out, &scan); err != nil {
		return nil, fmt.Errorf("reading OSV-Scanner's output: %w", err)
	}
	var pkgs []lockedPackage
	for _, r := range scan.Results {
		rel, err := filepath.Rel(root, r.Source.Path)
		if err != nil || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("OSV-Scanner reported %q, outside %s", r.Source.Path, root)
		}
		owner, rest, _ := strings.Cut(filepath.ToSlash(rel), "/")
		repo, lockfile, _ := strings.Cut(rest, "/")
		for _, p := range r.Packages {
			pkgs = append(pkgs, lockedPackage{
				Repository: owner + "/" + repo,
				Lockfile:   lockfile,
				Ecosystem:  p.Package.Ecosystem,
				Name:       p.Package.Name,
				Version:    p.Package.Version,
			})
		}
	}
	return pkgs, nil
}

func scanLockfiles(ctx context.Context, scanner, root, tmp string) ([]lockedPackage, error) {
	cmd := exec.CommandContext(ctx, scanner, "scan", "source", "--recursive",
		"--offline", "--no-resolve", "--no-call-analysis=all", "--x-disable-plugins", "vulnmatch/osvlocal",
		"--allow-no-lockfiles", "--all-packages", "--format", "json", "--verbosity", "error", root)
	cmd.Env = []string{"TMPDIR=" + tmp, "HOME=" + tmp}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("osv-scanner: %w: %s", err, strings.TrimSpace(tail(stderr.String(), 2048)))
	}
	return parseScan(stdout.Bytes(), root)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

type listing struct {
	lockedPackage
	Advisory string
}

func maliciousListings(db *advisoryDB, pkgs []lockedPackage) []listing {
	seen := map[listing]bool{}
	var out []listing
	for _, p := range pkgs {
		for _, a := range db.lookup(p.Ecosystem, p.Name) {
			if !a.Malicious || !a.affects(p.Ecosystem, p.Version) {
				continue
			}
			l := listing{p, a.ID}
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Repository+"\x00"+a.Lockfile+"\x00"+a.Name+"\x00"+a.Version+"\x00"+a.Advisory <
			b.Repository+"\x00"+b.Lockfile+"\x00"+b.Name+"\x00"+b.Version+"\x00"+b.Advisory
	})
	return out
}

func postAlerts(ctx context.Context, client *http.Client, alertmanager string, alertFor time.Duration, ls []listing, now time.Time) error {
	if len(ls) == 0 {
		return nil
	}
	type alert struct {
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"startsAt"`
		EndsAt      time.Time         `json:"endsAt"`
	}
	alerts := make([]alert, 0, len(ls))
	for _, l := range ls {
		alerts = append(alerts, alert{
			Labels: map[string]string{
				"alertname":  "LockedVersionListedMalicious",
				"severity":   "critical",
				"repository": l.Repository,
				"lockfile":   l.Lockfile,
				"ecosystem":  l.Ecosystem,
				"package":    l.Name,
				"version":    l.Version,
				"advisory":   l.Advisory,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s %s@%s, locked in %s %s, is listed as malicious by %s",
					l.Ecosystem, l.Name, l.Version, l.Repository, l.Lockfile, l.Advisory),
				"description": "via-maris refuses every later install of this version. Remove it from the lockfile, and treat every machine that installed it as exposed.",
			},
			StartsAt: now,
			EndsAt:   now.Add(alertFor),
		})
	}
	body, err := json.Marshal(alerts)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, alertmanager+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("posting %d alerts: %s %s", len(alerts), resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

type inUseObject struct {
	Generated      time.Time                                  `json:"generated"`
	Ecosystems     map[string]map[string][]string             `json:"ecosystems"`
	RecordsThrough time.Time                                  `json:"recordsThrough"`
	Served         map[string]map[string]map[string]time.Time `json:"served"`
}

func recordKeyTime(prefix, key string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return time.Time{}, false
	}
	date, name, ok := strings.Cut(rest, "/")
	if !ok || len(name) < len("150405.000000000") {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 150405.000000000", date+" "+name[:len("150405.000000000")])
	return t, err == nil
}

func readServed(ctx context.Context, store *objectStore, prefix string, overlap, window time.Duration, prev *inUseObject, now time.Time) (map[string]map[string]map[string]time.Time, time.Time, int, error) {
	served := map[string]map[string]map[string]time.Time{}
	from := now.Add(-window)
	through := from
	if prev != nil && prev.RecordsThrough.After(from) {
		through = prev.RecordsThrough
		from = prev.RecordsThrough.Add(-overlap)
		for eco, pkgs := range prev.Served {
			for name, vs := range pkgs {
				for v, at := range vs {
					markServed(served, eco, name, v, at)
				}
			}
		}
	}
	read := 0
	for day := from.UTC().Truncate(24 * time.Hour); !day.After(now); day = day.Add(24 * time.Hour) {
		dayPrefix := prefix + day.Format("2006-01-02") + "/"
		keys, err := store.list(ctx, dayPrefix, "")
		if err != nil {
			return nil, time.Time{}, 0, err
		}
		for _, key := range keys {
			at, ok := recordKeyTime(prefix, key)
			if !ok || at.Before(from) {
				continue
			}
			if err := readRecords(ctx, store, key, served); err != nil {
				return nil, time.Time{}, 0, err
			}
			read++
			if at.After(through) {
				through = at
			}
		}
	}
	cut := now.Add(-window)
	for eco, pkgs := range served {
		for name, vs := range pkgs {
			for v, at := range vs {
				if at.Before(cut) {
					delete(vs, v)
				}
			}
			if len(vs) == 0 {
				delete(pkgs, name)
			}
		}
		if len(pkgs) == 0 {
			delete(served, eco)
		}
	}
	return served, through, read, nil
}

func markServed(served map[string]map[string]map[string]time.Time, eco, name, version string, at time.Time) {
	if served[eco] == nil {
		served[eco] = map[string]map[string]time.Time{}
	}
	if served[eco][name] == nil {
		served[eco][name] = map[string]time.Time{}
	}
	if at.After(served[eco][name][version]) {
		served[eco][name][version] = at
	}
}

func readRecords(ctx context.Context, store *objectStore, key string, served map[string]map[string]map[string]time.Time) error {
	body, err := store.get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if !r.Served || r.Kind != "artifact" || r.Version == "" || !(&Upstream{Ecosystem: r.Ecosystem}).checked() {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, r.Time)
		if err != nil {
			return fmt.Errorf("%s: record time %q: %w", key, r.Time, err)
		}
		markServed(served, r.Ecosystem, packageKey(r.Ecosystem, r.Package), r.Version, at)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func inUseVersions(locked []lockedPackage, served map[string]map[string]map[string]time.Time, ecosystems []string) map[string]map[string][]string {
	want := map[string]bool{}
	for _, eco := range ecosystems {
		want[eco] = true
	}
	set := map[string]map[string]map[string]bool{}
	add := func(eco, name, v string) {
		if !want[eco] || v == "" {
			return
		}
		if set[eco] == nil {
			set[eco] = map[string]map[string]bool{}
		}
		k := packageKey(eco, name)
		if set[eco][k] == nil {
			set[eco][k] = map[string]bool{}
		}
		set[eco][k][v] = true
	}
	for _, p := range locked {
		add(p.Ecosystem, p.Name, p.Version)
	}
	for eco, pkgs := range served {
		for name, vs := range pkgs {
			for v := range vs {
				add(eco, name, v)
			}
		}
	}
	out := map[string]map[string][]string{}
	for eco, pkgs := range set {
		out[eco] = map[string][]string{}
		for name, vs := range pkgs {
			list := make([]string, 0, len(vs))
			for v := range vs {
				list = append(list, v)
			}
			sort.Strings(list)
			out[eco][name] = list
		}
	}
	return out
}

func readInUse(ctx context.Context, store *objectStore, object string) (*inUseObject, string, error) {
	body, etag, err := store.getTagged(ctx, object)
	if err != nil {
		return nil, "", err
	}
	defer body.Close()
	var o inUseObject
	if err := json.NewDecoder(body).Decode(&o); err != nil {
		return nil, etag, fmt.Errorf("%s: %w", object, err)
	}
	return &o, etag, nil
}

type recheckSources struct {
	fetchAll func(ctx context.Context, root string) (int, error)
	scan     func(ctx context.Context, root, tmp string) ([]lockedPackage, error)
}

type recheckRun struct {
	cfg     *RecheckConfig
	client  *http.Client
	db      *advisoryDB
	inUse   *objectStore
	records *objectStore
	src     recheckSources
}

func newRecheckRun(cfg *RecheckConfig, client *http.Client) (*recheckRun, error) {
	key, err := parseAppKey(os.Getenv(cfg.GitHub.PrivateKeyEnv))
	if err != nil {
		return nil, err
	}
	app := &githubApp{
		api:            cfg.GitHub.API,
		appID:          os.Getenv(cfg.GitHub.AppIDEnv),
		installationID: os.Getenv(cfg.GitHub.InstallationIDEnv),
		key:            key,
		client:         client,
	}
	run := &recheckRun{
		cfg:     cfg,
		client:  client,
		db:      &advisoryDB{source: cfg.Advisories.Source, client: client, eco: map[string]*ecosystemData{}},
		inUse:   newObjectStore(cfg.InUse.Store, client),
		records: newObjectStore(cfg.Records.Store, client),
	}
	run.src = recheckSources{
		fetchAll: func(ctx context.Context, root string) (int, error) {
			if err := app.mint(ctx); err != nil {
				return 0, err
			}
			repos, err := app.repositories(ctx, cfg.GitHub.Owner)
			if err != nil {
				return 0, err
			}
			n := 0
			for _, r := range repos {
				err := app.fetch(ctx, r, filepath.Join(root, filepath.FromSlash(r.FullName)))
				if errors.Is(err, errEmptyRepository) {
					log.Printf("recheck: %s: %v", r.FullName, err)
					continue
				}
				if err != nil {
					return 0, err
				}
				n++
			}
			return n, nil
		},
		scan: func(ctx context.Context, root, tmp string) ([]lockedPackage, error) {
			return scanLockfiles(ctx, cfg.OSVScanner, root, tmp)
		},
	}
	return run, nil
}

func (r *recheckRun) run(ctx context.Context) error {
	start := time.Now().UTC()
	for _, eco := range r.cfg.Ecosystems {
		if err := r.db.load(ctx, eco); err != nil {
			return fmt.Errorf("advisories %s: %w", eco, err)
		}
	}
	work, err := os.MkdirTemp(r.cfg.WorkDir, "pass-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	root, tmp := filepath.Join(work, "src"), filepath.Join(work, "tmp")
	for _, dir := range []string{root, tmp} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
	}
	repos, err := r.src.fetchAll(ctx, root)
	if err != nil {
		return err
	}
	locked, err := r.src.scan(ctx, root, tmp)
	if err != nil {
		return err
	}
	lockfiles := map[string]bool{}
	for _, p := range locked {
		lockfiles[p.Repository+"/"+p.Lockfile] = true
	}
	ls := maliciousListings(r.db, locked)
	log.Printf("recheck: %d repositories, %d lockfiles, %d package entries, %d malicious listings", repos, len(lockfiles), len(locked), len(ls))
	for _, l := range ls {
		log.Printf("recheck: %s %s@%s (%s) locked in %s %s", l.Ecosystem, l.Name, l.Version, l.Advisory, l.Repository, l.Lockfile)
	}
	if err := postAlerts(ctx, r.client, r.cfg.Alertmanager, r.cfg.AlertFor.Duration, ls, start); err != nil {
		return err
	}

	prev, etag, err := readInUse(ctx, r.inUse, r.cfg.InUse.Object)
	condition, value := "If-Match", etag
	switch {
	case errors.Is(err, errNoObject):
		condition, value = "If-None-Match", "*"
		fallthrough
	case err != nil && etag != "":
		log.Printf("recheck: the previous in-use set is unreadable, so the served versions are rebuilt from %s of records: %v", r.cfg.ServedWindow.Duration, err)
	case err != nil:
		return fmt.Errorf("reading the previous in-use set: %w", err)
	case etag == "":
		return fmt.Errorf("the store returned %s without an ETag, so this pass cannot write it without risking a newer set", r.cfg.InUse.Object)
	}
	served, through, objects, err := readServed(ctx, r.records, r.cfg.Records.Prefix, r.cfg.Records.Overlap.Duration, r.cfg.ServedWindow.Duration, prev, start)
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}
	set := inUseObject{
		Generated:      start,
		Ecosystems:     inUseVersions(locked, served, r.cfg.Ecosystems),
		RecordsThrough: through,
		Served:         served,
	}
	body, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if err := r.inUse.putIf(ctx, r.cfg.InUse.Object, "application/json", body, condition, value); err != nil {
		if errors.Is(err, errObjectChanged) {
			return fmt.Errorf("another pass wrote %s after this one read it, so this pass's set is dropped: %w", r.cfg.InUse.Object, err)
		}
		return err
	}
	n := 0
	for _, pkgs := range set.Ecosystems {
		for _, vs := range pkgs {
			n += len(vs)
		}
	}
	log.Printf("recheck: in-use set of %d versions in %d bytes, from %d record objects, generated %s", n, len(body), objects, start.Format(time.RFC3339))
	return nil
}

func recheckMain(path string, client *http.Client) error {
	cfg, err := loadRecheckConfig(path)
	if err != nil {
		return err
	}
	run, err := newRecheckRun(cfg, client)
	if err != nil {
		return err
	}
	return run.run(context.Background())
}
