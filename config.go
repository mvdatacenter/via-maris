package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
}

func (u *Upstream) checked() bool {
	return u.Ecosystem == "npm" || u.Ecosystem == "PyPI" || u.Ecosystem == "Go"
}

type Store struct {
	Endpoint           string `json:"endpoint"`
	EndpointEnv        string `json:"endpointEnv"`
	Region             string `json:"region"`
	Bucket             string `json:"bucket"`
	AccessKeyIDEnv     string `json:"accessKeyIdEnv"`
	SecretAccessKeyEnv string `json:"secretAccessKeyEnv"`
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
	return nil
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
		return fmt.Errorf("%s: ecosystem %q is not npm, PyPI, Go, apt or files", where, u.Ecosystem)
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
