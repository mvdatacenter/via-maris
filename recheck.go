package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RecheckConfig struct {
	GitHub struct {
		API               string `json:"api"`
		Org               string `json:"org"`
		AppIDEnv          string `json:"appIdEnv"`
		InstallationIDEnv string `json:"installationIdEnv"`
		PrivateKeyEnv     string `json:"privateKeyEnv"`
	} `json:"github"`
	Scanner struct {
		Path    string `json:"path"`
		WorkDir string `json:"workDir"`
	} `json:"scanner"`
	Alertmanager struct {
		URL          string   `json:"url"`
		ResolveAfter Duration `json:"resolveAfter"`
	} `json:"alertmanager"`
	InUse struct {
		Store  Store  `json:"store"`
		Object string `json:"object"`
	} `json:"inUse"`
	Records struct {
		Store  Store    `json:"store"`
		Prefix string   `json:"prefix"`
		Window Duration `json:"window"`
	} `json:"records"`
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
	gh := c.GitHub
	if !httpURL(gh.API) || gh.Org == "" {
		return errors.New("github needs an http(s) api URL without a trailing slash and an org")
	}
	for _, env := range []string{gh.AppIDEnv, gh.InstallationIDEnv, gh.PrivateKeyEnv} {
		if env == "" || os.Getenv(env) == "" {
			return errors.New("github: appIdEnv, installationIdEnv and privateKeyEnv must name environment variables that are set")
		}
	}
	if !filepath.IsAbs(c.Scanner.Path) || !filepath.IsAbs(c.Scanner.WorkDir) {
		return errors.New("scanner needs an absolute path and workDir")
	}
	if !httpURL(c.Alertmanager.URL) || c.Alertmanager.ResolveAfter.Duration <= 0 {
		return errors.New("alertmanager needs an http(s) url without a trailing slash and a positive resolveAfter")
	}
	if err := c.InUse.Store.validate("inUse"); err != nil {
		return err
	}
	if c.InUse.Object == "" {
		return errors.New("inUse needs an object")
	}
	if err := c.Records.Store.validate("records"); err != nil {
		return err
	}
	if c.Records.Prefix == "" || c.Records.Window.Duration <= 0 {
		return errors.New("records needs a prefix and a positive window")
	}
	return nil
}

type recheck struct {
	cfg     *RecheckConfig
	client  *http.Client
	inUse   *objectStore
	records *objectStore
	start   time.Time
}

type finding struct {
	repository, lockfile, ecosystem, pkg, version string
}

type recheckResult struct {
	repositories, lockfiles, locked, served int
	set                                     *inUseFile
	findings                                map[finding][]string
}

func (rc *recheck) run(ctx context.Context) (*recheckResult, error) {
	prev, err := rc.previousSet(ctx)
	if err != nil {
		return nil, err
	}
	token, err := rc.installationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("github app token: %w", err)
	}
	repos, err := rc.repositories(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}
	root := filepath.Join(rc.cfg.Scanner.WorkDir, "repos")
	if err := os.RemoveAll(root); err != nil {
		return nil, err
	}
	for _, repo := range repos {
		if err := rc.fetch(ctx, token, repo, filepath.Join(root, repo.Name)); err != nil {
			return nil, fmt.Errorf("%s: %w", repo.FullName, err)
		}
	}
	scan, err := rc.scan(ctx, root)
	if err != nil {
		return nil, err
	}
	res := &recheckResult{repositories: len(repos), findings: map[finding][]string{}}
	locked := map[string]map[string]map[string]bool{}
	for _, r := range scan.Results {
		rel, err := filepath.Rel(root, r.Source.Path)
		if err != nil || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("the scanner reported %s, outside %s", r.Source.Path, root)
		}
		repo, lockfile, _ := strings.Cut(filepath.ToSlash(rel), "/")
		res.lockfiles++
		for _, p := range r.Packages {
			eco, name, v := p.Package.Ecosystem, p.Package.Name, p.Package.Version
			if v == "" {
				continue
			}
			if eco == "npm" || eco == "PyPI" || eco == "Go" {
				addVersion(locked, eco, packageKey(eco, name), v)
				res.locked++
			}
			for _, vuln := range p.Vulnerabilities {
				if strings.HasPrefix(vuln.ID, "MAL-") {
					f := finding{repo, lockfile, eco, name, v}
					res.findings[f] = append(res.findings[f], vuln.ID)
				}
			}
		}
	}
	served, through, n, err := rc.servedVersions(ctx, prev)
	if err != nil {
		return nil, fmt.Errorf("decision records: %w", err)
	}
	res.served = n
	for eco, pkgs := range served {
		for name, vs := range pkgs {
			for v := range vs {
				addVersion(locked, eco, name, v)
			}
		}
	}
	set := &inUseFile{Generated: rc.start, Ecosystems: map[string]map[string][]string{}, RecordsThrough: through, Served: served}
	for eco, pkgs := range locked {
		set.Ecosystems[eco] = map[string][]string{}
		for name, vs := range pkgs {
			for v := range vs {
				set.Ecosystems[eco][name] = append(set.Ecosystems[eco][name], v)
			}
			sort.Strings(set.Ecosystems[eco][name])
		}
	}
	res.set = set
	body, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	if err := rc.inUse.put(ctx, rc.cfg.InUse.Object, "application/json", body); err != nil {
		return nil, err
	}
	if err := rc.alert(ctx, res.findings); err != nil {
		return res, fmt.Errorf("alertmanager: %w", err)
	}
	return res, nil
}

func addVersion(m map[string]map[string]map[string]bool, eco, name, v string) {
	if m[eco] == nil {
		m[eco] = map[string]map[string]bool{}
	}
	if m[eco][name] == nil {
		m[eco][name] = map[string]bool{}
	}
	m[eco][name][v] = true
}

func (rc *recheck) previousSet(ctx context.Context) (*inUseFile, error) {
	body, err := rc.inUse.get(ctx, rc.cfg.InUse.Object)
	if errors.Is(err, errNoObject) {
		return &inUseFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var f inUseFile
	if err := json.NewDecoder(body).Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", rc.cfg.InUse.Object, err)
	}
	return &f, nil
}

// recordLookback re-reads records named this long before the newest one the
// last run read. A record object is named when its upload starts, so one from
// another replica can land after a later-named one was listed; reading a
// record twice changes nothing.
const recordLookback = 10 * time.Minute

const recordKeyTime = "2006-01-02/150405.000000000"

func (rc *recheck) servedVersions(ctx context.Context, prev *inUseFile) (map[string]map[string]map[string]time.Time, time.Time, int, error) {
	since := rc.start.Add(-rc.cfg.Records.Window.Duration)
	served := map[string]map[string]map[string]time.Time{}
	for eco, pkgs := range prev.Served {
		for name, vs := range pkgs {
			for v, at := range vs {
				if !at.Before(since) {
					setServed(served, eco, name, v, at)
				}
			}
		}
	}
	from := since
	if t := prev.RecordsThrough.Add(-recordLookback); t.After(from) {
		from = t
	}
	prefix := rc.cfg.Records.Prefix
	keys, err := rc.records.list(ctx, prefix, prefix+from.UTC().Format(recordKeyTime))
	if err != nil {
		return nil, time.Time{}, 0, err
	}
	through, n := prev.RecordsThrough, 0
	for _, key := range keys {
		stamp := strings.TrimPrefix(key, prefix)
		if len(stamp) < len(recordKeyTime) {
			continue
		}
		at, err := time.Parse(recordKeyTime, stamp[:len(recordKeyTime)])
		if err != nil {
			continue
		}
		body, err := rc.records.get(ctx, key)
		if err != nil {
			return nil, time.Time{}, 0, err
		}
		b, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			return nil, time.Time{}, 0, err
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			var r record
			if json.Unmarshal(line, &r) != nil || !r.Served || r.Kind != "artifact" || r.Version == "" {
				continue
			}
			if r.Ecosystem != "npm" && r.Ecosystem != "PyPI" && r.Ecosystem != "Go" {
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, r.Time)
			if err != nil || t.Before(since) {
				continue
			}
			setServed(served, r.Ecosystem, packageKey(r.Ecosystem, r.Package), r.Version, t)
			n++
		}
		if at.After(through) {
			through = at
		}
	}
	return served, through, n, nil
}

func setServed(m map[string]map[string]map[string]time.Time, eco, name, v string, at time.Time) {
	if m[eco] == nil {
		m[eco] = map[string]map[string]time.Time{}
	}
	if m[eco][name] == nil {
		m[eco][name] = map[string]time.Time{}
	}
	if at.After(m[eco][name][v]) {
		m[eco][name][v] = at.UTC()
	}
}

func (rc *recheck) githubRequest(ctx context.Context, method, url, auth string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return rc.client.Do(req)
}

func githubDecode(resp *http.Response, v any) error {
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s %s", resp.Request.Method, resp.Request.URL, resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (rc *recheck) installationToken(ctx context.Context) (string, error) {
	gh := rc.cfg.GitHub
	key, err := parseRSAKey([]byte(os.Getenv(gh.PrivateKeyEnv)))
	if err != nil {
		return "", fmt.Errorf("%s: %w", gh.PrivateKeyEnv, err)
	}
	jwt, err := appJWT(os.Getenv(gh.AppIDEnv), key, time.Now())
	if err != nil {
		return "", err
	}
	url := gh.API + "/app/installations/" + os.Getenv(gh.InstallationIDEnv) + "/access_tokens"
	resp, err := rc.githubRequest(ctx, http.MethodPost, url, "Bearer "+jwt, []byte(`{"permissions":{"contents":"read"}}`))
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := githubDecode(resp, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("the token response carried no token")
	}
	return out.Token, nil
}

func parseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

// The issue time is set a minute back for clock drift.
func appJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	var iss any = appID
	if n, err := strconv.ParseInt(appID, 10, 64); err == nil {
		iss = n
	}
	claims, err := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": iss})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

type repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Archived bool   `json:"archived"`
	Size     int    `json:"size"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (rc *recheck) repositories(ctx context.Context, token string) ([]repository, error) {
	var out []repository
	for page := 1; ; page++ {
		resp, err := rc.githubRequest(ctx, http.MethodGet, fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", rc.cfg.GitHub.API, page), "Bearer "+token, nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Repositories []repository `json:"repositories"`
		}
		if err := githubDecode(resp, &body); err != nil {
			return nil, err
		}
		for _, r := range body.Repositories {
			if !r.Archived && strings.EqualFold(r.Owner.Login, rc.cfg.GitHub.Org) {
				out = append(out, r)
			}
		}
		if len(body.Repositories) < 100 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// maxExtractedFile skips any file larger than this. No lockfile comes near it,
// and it bounds what one repository's tarball can write.
const maxExtractedFile = 64 << 20

// A tarball needs no git in the image.
func (rc *recheck) fetch(ctx context.Context, token string, repo repository, dst string) error {
	resp, err := rc.githubRequest(ctx, http.MethodGet, rc.cfg.GitHub.API+"/repos/"+repo.FullName+"/tarball", "Bearer "+token, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// An empty repository has no default branch to archive.
	if resp.StatusCode == http.StatusNotFound && repo.Size == 0 {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET tarball: %s %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxExtractedFile {
			continue
		}
		// Every entry sits under one top directory named for the commit.
		_, rel, ok := strings.Cut(h.Name, "/")
		if !ok || !filepath.IsLocal(rel) {
			continue
		}
		path := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, maxExtractedFile))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}

type scanReport struct {
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
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// --all-packages lists clean packages too, which the in-use set needs.
func (rc *recheck) scan(ctx context.Context, root string) (*scanReport, error) {
	work := rc.cfg.Scanner.WorkDir
	tmp := filepath.Join(work, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, err
	}
	out := filepath.Join(work, "scan.json")
	os.Remove(out)
	cmd := exec.CommandContext(ctx, rc.cfg.Scanner.Path, "scan", "source", "-r", "--all-packages",
		"--offline-vulnerabilities", "--download-offline-databases", "--format", "json", "--output-file", out, root)
	cmd.Env = []string{"HOME=" + work, "TMPDIR=" + tmp, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + filepath.Join(work, "osvdb")}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	err := cmd.Run()
	// OSV-Scanner exits 1 when it lists a vulnerability, and 128 when it finds
	// no lockfile at all, in which case it writes no report.
	var exit *exec.ExitError
	switch {
	case err == nil, errors.As(err, &exit) && exit.ExitCode() == 1:
	case errors.As(err, &exit) && exit.ExitCode() == 128:
		return &scanReport{}, nil
	default:
		return nil, fmt.Errorf("osv-scanner: %w", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	var rep scanReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("osv-scanner report: %w", err)
	}
	return &rep, nil
}

func (rc *recheck) alert(ctx context.Context, findings map[finding][]string) error {
	if len(findings) == 0 {
		return nil
	}
	type amAlert struct {
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		// Without startsAt, Alertmanager starts the alert at its endsAt.
		StartsAt time.Time `json:"startsAt"`
		EndsAt   time.Time `json:"endsAt"`
	}
	now := time.Now().UTC()
	var alerts []amAlert
	for f, ids := range findings {
		sort.Strings(ids)
		adv := strings.Join(slices.Compact(ids), ",")
		alerts = append(alerts, amAlert{
			Labels: map[string]string{
				"alertname": "LockedVersionListedMalicious", "severity": "critical",
				"repository": f.repository, "lockfile": f.lockfile, "ecosystem": f.ecosystem,
				"package": f.pkg, "version": f.version, "advisory": adv,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s/%s %s locks %s@%s, listed as malicious by %s", rc.cfg.GitHub.Org, f.repository, f.lockfile, f.pkg, f.version, adv),
			},
			StartsAt: now,
			EndsAt:   now.Add(rc.cfg.Alertmanager.ResolveAfter.Duration),
		})
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Annotations["summary"] < alerts[j].Annotations["summary"] })
	body, err := json.Marshal(alerts)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rc.cfg.Alertmanager.URL+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST /api/v2/alerts: %s %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func recheckMain(path string) {
	cfg, err := loadRecheckConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	client := newClient()
	rc := &recheck{
		cfg:     cfg,
		client:  client,
		inUse:   newObjectStore(cfg.InUse.Store, client),
		records: newObjectStore(cfg.Records.Store, client),
		start:   time.Now().UTC(),
	}
	ctx, stop := signalContext()
	defer stop()
	res, err := rc.run(ctx)
	if res != nil {
		n := 0
		for _, pkgs := range res.set.Ecosystems {
			for _, vs := range pkgs {
				n += len(vs)
			}
		}
		log.Printf("recheck %s: %d repositories, %d lockfiles, %d locked entries, %d served records read; in-use set of %d versions written; %d malicious listings",
			version, res.repositories, res.lockfiles, res.locked, res.served, n, len(res.findings))
	}
	if err != nil {
		log.Fatal(err)
	}
}
