package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Date struct{ time.Time }

func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return err
	}
	d.Time = v
	return nil
}

type Exception struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	Reason   string `json:"reason"`
	Reviewed string `json:"reviewed"`
	Expires  Date   `json:"expires"`
}

type PinnedFile struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Upstream struct {
	Name        string       `json:"name"`
	Ecosystem   string       `json:"ecosystem"`
	URL         string       `json:"url"`
	Files       string       `json:"files"`
	Index       string       `json:"index"`
	SumDB       string       `json:"sumdb"`
	IndexPoll   Duration     `json:"indexPoll"`
	IndexMaxAge Duration     `json:"indexMaxAge"`
	Hold        Duration     `json:"hold"`
	Advisories  string       `json:"advisories"`
	Exceptions  []Exception  `json:"exceptions"`
	Pinned      []PinnedFile `json:"pinned"`
	Held        string       `json:"held"`
}

func (u *Upstream) checked() bool {
	return u.Ecosystem == "npm" || u.Ecosystem == "PyPI" || u.Ecosystem == "Go" || u.Ecosystem == "Maven"
}

type Store struct {
	Endpoint           string `json:"endpoint"`
	EndpointEnv        string `json:"endpointEnv"`
	Region             string `json:"region"`
	Bucket             string `json:"bucket"`
	AccessKeyIDEnv     string `json:"accessKeyIdEnv"`
	SecretAccessKeyEnv string `json:"secretAccessKeyEnv"`
}

type ByName struct {
	Listen   string       `json:"listen"`
	Upstream string       `json:"upstream"`
	Cert     string       `json:"cert"`
	Key      string       `json:"key"`
	CA       string       `json:"ca"`
	NPM      *NPMByName   `json:"npm"`
	Maven    *MavenByName `json:"maven"`
}

type NPMByName struct {
	Upstream string   `json:"upstream"`
	Hosts    []string `json:"hosts"`
	Cert     string   `json:"cert"`
	Key      string   `json:"key"`
	CA       string   `json:"ca"`
}

type MavenByName struct {
	Upstreams []string `json:"upstreams"`
	Files     string   `json:"files"`
	Listings  []string `json:"listings"`
	Cert      string   `json:"cert"`
	Key       string   `json:"key"`
	CA        string   `json:"ca"`
}

type Config struct {
	Listen     string `json:"listen"`
	Advisories struct {
		Source  string   `json:"source"`
		Refresh Duration `json:"refresh"`
		MaxAge  Duration `json:"maxAge"`
	} `json:"advisories"`
	InUse struct {
		Store   Store    `json:"store"`
		Object  string   `json:"object"`
		Refresh Duration `json:"refresh"`
		MaxAge  Duration `json:"maxAge"`
	} `json:"inUse"`
	Records struct {
		Store        Store    `json:"store"`
		Prefix       string   `json:"prefix"`
		Interval     Duration `json:"interval"`
		MaxUnshipped Duration `json:"maxUnshipped"`
	} `json:"records"`
	Upstreams []Upstream `json:"upstreams"`
	ByName    *ByName    `json:"byName"`
}

var (
	upstreamName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	hexDigest    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
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

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && !strings.HasSuffix(s, "/")
}

func (s *Store) validate(where string) error {
	if s.EndpointEnv != "" {
		if s.Endpoint != "" {
			return fmt.Errorf("%s.store names both endpoint and endpointEnv", where)
		}
		s.Endpoint = os.Getenv(s.EndpointEnv)
		if !httpURL(s.Endpoint) {
			return fmt.Errorf("%s.store: endpointEnv names %s, which must be set to an http(s) endpoint without a trailing slash", where, s.EndpointEnv)
		}
	}
	if !httpURL(s.Endpoint) || s.Region == "" || s.Bucket == "" {
		return fmt.Errorf("%s.store needs an http(s) endpoint without a trailing slash, a region and a bucket", where)
	}
	for _, env := range []string{s.AccessKeyIDEnv, s.SecretAccessKeyEnv} {
		if env == "" || os.Getenv(env) == "" {
			return fmt.Errorf("%s.store: accessKeyIdEnv and secretAccessKeyEnv must name environment variables that are set", where)
		}
	}
	return nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if !httpURL(c.Advisories.Source) {
		return errors.New("advisories.source must be an http(s) URL without a trailing slash")
	}
	if c.Advisories.Refresh.Duration <= 0 || c.Advisories.MaxAge.Duration <= c.Advisories.Refresh.Duration {
		return errors.New("advisories.maxAge must exceed a positive advisories.refresh")
	}
	if err := c.InUse.Store.validate("inUse"); err != nil {
		return err
	}
	if c.InUse.Object == "" || c.InUse.Refresh.Duration <= 0 || c.InUse.MaxAge.Duration <= c.InUse.Refresh.Duration {
		return errors.New("inUse needs an object, and a maxAge exceeding a positive refresh")
	}
	if err := c.Records.Store.validate("records"); err != nil {
		return err
	}
	if c.Records.Interval.Duration <= 0 || c.Records.MaxUnshipped.Duration <= c.Records.Interval.Duration {
		return errors.New("records.maxUnshipped must exceed a positive records.interval")
	}
	if len(c.Upstreams) == 0 {
		return errors.New("upstreams is empty")
	}
	seen := map[string]bool{}
	for i := range c.Upstreams {
		if err := c.Upstreams[i].validate(seen); err != nil {
			return err
		}
	}
	if c.ByName != nil {
		return c.ByName.validate(c)
	}
	return nil
}

func (b *ByName) validate(c *Config) error {
	if b.Listen == "" || b.Listen == c.Listen {
		return errors.New("byName.listen is required and differs from listen")
	}
	if b.Cert == "" || b.Key == "" || b.CA == "" {
		return errors.New("byName needs cert, key and ca files")
	}
	for _, u := range c.Upstreams {
		if u.Name != b.Upstream {
			continue
		}
		if u.Ecosystem != "PyPI" {
			return fmt.Errorf("byName.upstream %s is not a PyPI upstream", b.Upstream)
		}
		index, _ := url.Parse(u.URL)
		files, _ := url.Parse(u.Files)
		if index.Hostname() == files.Hostname() {
			return fmt.Errorf("byName.upstream %s serves its index and files from one host, so its requests cannot be told apart by name", b.Upstream)
		}
		taken := []string{index.Hostname(), files.Hostname()}
		if b.NPM != nil {
			if err := b.NPM.validate(c, taken...); err != nil {
				return err
			}
			taken = append(taken, b.NPM.Hosts...)
		}
		if b.Maven != nil {
			return b.Maven.validate(c, taken)
		}
		return nil
	}
	return fmt.Errorf("byName.upstream %q names no upstream", b.Upstream)
}

type mavenRoot struct {
	host, path string
}

func splitRoot(s string) (mavenRoot, bool) {
	u, err := url.Parse(s)
	if err != nil || !httpURL(s) || u.RawQuery != "" || u.Fragment != "" {
		return mavenRoot{}, false
	}
	return mavenRoot{u.Hostname(), u.EscapedPath()}, true
}

func (r mavenRoot) contains(o mavenRoot) bool {
	return r.host == o.host && strings.HasPrefix(o.path+"/", r.path+"/")
}

func upstreamIn(c *Config, name string) *Upstream {
	for i := range c.Upstreams {
		if c.Upstreams[i].Name == name {
			return &c.Upstreams[i]
		}
	}
	return nil
}

func (m *MavenByName) hosts(c *Config) []string {
	var urls []string
	for _, name := range m.Upstreams {
		if up := upstreamIn(c, name); up != nil {
			urls = append(urls, up.URL)
		}
	}
	urls = append(urls, m.Listings...)
	if files := upstreamIn(c, m.Files); files != nil {
		for _, f := range files.Pinned {
			urls = append(urls, f.URL)
		}
	}
	var out []string
	for _, s := range urls {
		if r, ok := splitRoot(s); ok && !slices.Contains(out, r.host) {
			out = append(out, r.host)
		}
	}
	return out
}

func (m *MavenByName) validate(c *Config, taken []string) error {
	if m.Cert == "" || m.Key == "" || m.CA == "" {
		return errors.New("byName.maven needs cert, key and ca files")
	}
	if len(m.Upstreams) == 0 {
		return errors.New("byName.maven.upstreams is empty")
	}
	var repos, listings []mavenRoot
	for i, name := range m.Upstreams {
		up := upstreamIn(c, name)
		switch {
		case up == nil:
			return fmt.Errorf("byName.maven.upstreams entry %q names no upstream", name)
		case up.Ecosystem != "Maven":
			return fmt.Errorf("byName.maven.upstreams entry %s is not a Maven upstream", name)
		case slices.Contains(m.Upstreams[:i], name):
			return fmt.Errorf("byName.maven.upstreams entry %s is repeated", name)
		}
		r, ok := splitRoot(up.URL)
		if !ok || r.path == "" {
			return fmt.Errorf("byName.maven: upstream %s url %q has a query or fragment, or no path", name, up.URL)
		}
		repos = append(repos, r)
	}
	for _, l := range m.Listings {
		r, ok := splitRoot(l)
		if !ok || r.path == "" {
			return fmt.Errorf("byName.maven: listing %q is not an http(s) URL with a path and no trailing slash, query or fragment", l)
		}
		listings = append(listings, r)
	}
	all := append(slices.Clone(repos), listings...)
	for i, a := range all {
		for _, b := range all[:i] {
			if a.contains(b) || b.contains(a) {
				return fmt.Errorf("byName.maven: %s%s and %s%s overlap", a.host, a.path, b.host, b.path)
			}
		}
	}
	if m.Files != "" {
		files := upstreamIn(c, m.Files)
		if files == nil || files.Ecosystem != "files" || files.Held == "" {
			return fmt.Errorf("byName.maven.files %q names no files upstream that holds its files", m.Files)
		}
		for _, f := range files.Pinned {
			r, ok := splitRoot(f.URL)
			if !ok {
				return fmt.Errorf("byName.maven: file %s url %q has a query or fragment", f.Name, f.URL)
			}
			for _, repo := range repos {
				if repo.contains(r) {
					return fmt.Errorf("byName.maven: file %s lies in a Maven repository, which serves it as an artifact", f.Name)
				}
			}
		}
	}
	for _, h := range m.hosts(c) {
		if slices.Contains(taken, h) {
			return fmt.Errorf("byName.maven serves %s, which is already a PyPI or npm name", h)
		}
	}
	return nil
}

func (n *NPMByName) validate(c *Config, pypiHosts ...string) error {
	if n.Cert == "" || n.Key == "" || n.CA == "" {
		return errors.New("byName.npm needs cert, key and ca files")
	}
	for _, u := range c.Upstreams {
		if u.Name != n.Upstream {
			continue
		}
		if u.Ecosystem != "npm" {
			return fmt.Errorf("byName.npm.upstream %s is not an npm upstream", n.Upstream)
		}
		registry, _ := url.Parse(u.URL)
		seen := map[string]bool{}
		for _, h := range n.Hosts {
			if h == "" || strings.ContainsAny(h, ":/") || seen[h] {
				return fmt.Errorf("byName.npm.hosts entry %q is not a bare host name, or is repeated", h)
			}
			for _, p := range pypiHosts {
				if h == p {
					return fmt.Errorf("byName.npm.hosts entry %s is already a PyPI name", h)
				}
			}
			seen[h] = true
		}
		if !seen[registry.Hostname()] {
			return fmt.Errorf("byName.npm.hosts must include %s, the host of upstream %s", registry.Hostname(), n.Upstream)
		}
		return nil
	}
	return fmt.Errorf("byName.npm.upstream %q names no upstream", n.Upstream)
}

func (u *Upstream) validate(seen map[string]bool) error {
	if !upstreamName.MatchString(u.Name) || seen[u.Name] || u.Name == "healthz" || u.Name == "metrics" {
		return fmt.Errorf("upstream name %q is not lower-case letters, digits and dashes, or is repeated or reserved", u.Name)
	}
	seen[u.Name] = true
	where := "upstream " + u.Name
	needURL := func(field, v string) error {
		if !httpURL(v) {
			return fmt.Errorf("%s: %s must be an http(s) URL without a trailing slash", where, field)
		}
		return nil
	}
	if u.Ecosystem == "files" {
		if u.URL != "" || u.Hold.Duration != 0 || u.Advisories != "" || len(u.Exceptions) > 0 {
			return fmt.Errorf("%s: a files upstream takes pinned files alone", where)
		}
		if u.Held != "" && !filepath.IsAbs(u.Held) {
			return fmt.Errorf("%s: held must be an absolute directory", where)
		}
		if len(u.Pinned) == 0 {
			return fmt.Errorf("%s pins no files", where)
		}
		names := map[string]bool{}
		for _, f := range u.Pinned {
			if f.Name == "" || names[f.Name] || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "..") {
				return fmt.Errorf("%s: file name %q is empty, repeated, absolute or climbs out", where, f.Name)
			}
			names[f.Name] = true
			if err := needURL("file "+f.Name+" url", f.URL); err != nil {
				return err
			}
			if !hexDigest.MatchString(f.SHA256) {
				return fmt.Errorf("%s: file %s needs a lower-case hex sha256", where, f.Name)
			}
		}
		return nil
	}
	if u.Ecosystem != "apt" && !u.checked() {
		return fmt.Errorf("%s: ecosystem %q is not npm, PyPI, Go, Maven, apt or files", where, u.Ecosystem)
	}
	if u.Held != "" {
		return fmt.Errorf("%s: only a files upstream holds files", where)
	}
	if err := needURL("url", u.URL); err != nil {
		return err
	}
	if u.Hold.Duration <= 0 {
		return fmt.Errorf("%s has no hold", where)
	}
	if len(u.Pinned) > 0 {
		return fmt.Errorf("%s: only a files upstream pins files", where)
	}
	if u.Ecosystem == "apt" {
		if u.Advisories != "" || len(u.Exceptions) > 0 {
			return fmt.Errorf("%s: an apt upstream is held by its snapshot date alone, and takes no advisories or exceptions", where)
		}
		return nil
	}
	if u.Advisories != "malicious" && u.Advisories != "all" {
		return fmt.Errorf("%s: advisories must be malicious or all", where)
	}
	for _, e := range u.Exceptions {
		if e.Package == "" || e.Version == "" || e.Reason == "" || e.Reviewed == "" || e.Expires.IsZero() {
			return fmt.Errorf("%s: an exception needs package, version, reason, reviewed and expires", where)
		}
	}
	switch u.Ecosystem {
	case "PyPI":
		return needURL("files", u.Files)
	case "Go":
		if err := needURL("index", u.Index); err != nil {
			return err
		}
		if err := needURL("sumdb", u.SumDB); err != nil {
			return err
		}
		if u.IndexPoll.Duration <= 0 || u.IndexMaxAge.Duration <= u.IndexPoll.Duration {
			return fmt.Errorf("%s: indexMaxAge must exceed a positive indexPoll", where)
		}
	}
	return nil
}
