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
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// docs/configuration.md, "The hold-lag report", describes every field and step.
type HoldLagConfig struct {
	GatewayConfig string   `json:"gatewayConfig"`
	Alertmanager  string   `json:"alertmanager"`
	AlertFor      Duration `json:"alertFor"`
	Target        float64  `json:"target"`
	Low           float64  `json:"low"`
	High          float64  `json:"high"`
	MinDated      int      `json:"minDated"`
	MaxHoldDays   int      `json:"maxHoldDays"`
	GoWindow      Duration `json:"goWindow"`
}

func loadHoldLagConfig(path string) (*HoldLagConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c HoldLagConfig
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

func (c *HoldLagConfig) validate() error {
	if c.GatewayConfig == "" {
		return errors.New("gatewayConfig is required")
	}
	if !httpURL(c.Alertmanager) || c.AlertFor.Duration <= 0 {
		return errors.New("alertmanager must be an http(s) URL without a trailing slash, and alertFor positive")
	}
	if !(0 < c.Low && c.Low < c.Target && c.Target < c.High && c.High < 1) {
		return errors.New("low, target and high must rise in that order between 0 and 1")
	}
	if c.MinDated <= 0 || c.MaxHoldDays <= 0 || c.GoWindow.Duration <= 0 {
		return errors.New("minDated, maxHoldDays and goWindow must be positive")
	}
	return nil
}

type holdLagGateway struct {
	source    string
	records   *objectStore
	prefix    string
	upstreams []*Upstream
}

func readHoldLagGateway(path string, client *http.Client) (*holdLagGateway, error) {
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
	if !httpURL(c.Advisories.Source) {
		return nil, fmt.Errorf("%s: advisories.source must be an http(s) URL without a trailing slash", path)
	}
	if err := c.Records.Store.validate("records"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	g := &holdLagGateway{source: c.Advisories.Source, records: newObjectStore(c.Records.Store, client), prefix: c.Records.Prefix}
	seen := map[string]bool{}
	ecosystems := map[string]bool{}
	for i := range c.Upstreams {
		up := &c.Upstreams[i]
		if err := up.validate(seen); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		// The first upstream of an ecosystem is the one measured; the
		// export and the records do not say which upstream served.
		if up.checked() && !ecosystems[up.Ecosystem] {
			ecosystems[up.Ecosystem] = true
			g.upstreams = append(g.upstreams, up)
		}
	}
	if len(g.upstreams) == 0 {
		return nil, fmt.Errorf("%s: no npm, PyPI or Go upstream to measure", path)
	}
	// npm comes first because PyPI's thin months follow its curve.
	order := map[string]int{"npm": 0, "PyPI": 1, "Go": 2}
	sort.Slice(g.upstreams, func(i, j int) bool { return order[g.upstreams[i].Ecosystem] < order[g.upstreams[j].Ecosystem] })
	return g, nil
}

type listedVersion struct {
	pkg, version string
	listed       time.Time
	advisory     string
}

type monthListings struct {
	entries    int
	noVersions int
	versions   []listedVersion
}

func readListings(ctx context.Context, client *http.Client, source, eco string, from, to time.Time) (*monthListings, error) {
	zr, err := fetchExport(ctx, client, source, eco)
	if err != nil {
		return nil, err
	}
	out := &monthListings{}
	byKey := map[string]int{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		var e osvEntry
		err = json.NewDecoder(rc).Decode(&e)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if !strings.HasPrefix(e.ID, "MAL-") {
			continue
		}
		published, err := time.Parse(time.RFC3339, e.Published)
		if err != nil || published.Before(from) || !published.Before(to) {
			continue
		}
		out.entries++
		named := false
		for _, a := range e.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			for _, v := range a.Versions {
				named = true
				k := packageKey(eco, a.Package.Name) + "@" + v
				if i, ok := byKey[k]; ok {
					if published.Before(out.versions[i].listed) {
						out.versions[i].listed, out.versions[i].advisory = published, e.ID
					}
					continue
				}
				byKey[k] = len(out.versions)
				out.versions = append(out.versions, listedVersion{a.Package.Name, v, published, e.ID})
			}
		}
		if !named {
			out.noVersions++
		}
	}
	sort.Slice(out.versions, func(i, j int) bool {
		a, b := out.versions[i], out.versions[j]
		if a.pkg != b.pkg {
			return a.pkg < b.pkg
		}
		return a.version < b.version
	})
	return out, nil
}

func recordedPublished(ctx context.Context, store *objectStore, prefix string, from, to time.Time) (map[string]time.Time, int, error) {
	out := map[string]time.Time{}
	objects := 0
	for d := from.UTC().Truncate(24 * time.Hour); d.Before(to); d = d.Add(24 * time.Hour) {
		keys, err := store.list(ctx, prefix+d.Format("2006-01-02")+"/", "")
		if err != nil {
			return nil, 0, err
		}
		for _, key := range keys {
			if err := readPublished(ctx, store, key, out); err != nil {
				return nil, 0, err
			}
			objects++
		}
	}
	return out, objects, nil
}

func readPublished(ctx context.Context, store *objectStore, key string, out map[string]time.Time) error {
	body, err := store.get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Published == "" || r.Version == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, r.Published)
		if err != nil {
			continue
		}
		k := r.Ecosystem + "\x00" + packageKey(r.Ecosystem, r.Package) + "@" + r.Version
		if cur, ok := out[k]; !ok || t.Before(cur) {
			out[k] = t
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

type dating struct {
	published    time.Time
	beforeWindow bool
}

var errRegistry = errors.New("registry")

func (r *holdLagRun) get(ctx context.Context, u, accept string) ([]byte, int, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Duration(attempt) * r.retryWait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, 0, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("User-Agent", "via-maris/"+version)
		resp, err := r.client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			last = err
		case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusGone:
			return body, resp.StatusCode, nil
		default:
			last = fmt.Errorf("%w: GET %s: %s", errRegistry, u, resp.Status)
		}
	}
	return nil, 0, last
}

// A package the registry no longer has returns no dates and no error, so the
// decision records date it.
func (r *holdLagRun) registryDates(ctx context.Context, up *Upstream, pkg string, versions []string) (map[string]dating, error) {
	out := map[string]dating{}
	switch up.Ecosystem {
	case "npm":
		body, status, err := r.get(ctx, up.URL+"/"+url.PathEscape(pkg), "application/json")
		if err != nil || status != http.StatusOK {
			return out, err
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", pkg, err)
		}
		for _, v := range versions {
			if t := npmPublished(doc, v); !t.IsZero() {
				out[v] = dating{published: t}
			}
		}
	case "PyPI":
		body, status, err := r.get(ctx, up.URL+"/pypi/"+url.PathEscape(pkg)+"/json", "application/json")
		if err != nil || status != http.StatusOK {
			return out, err
		}
		var doc struct {
			Releases map[string][]struct {
				Uploaded string `json:"upload_time_iso_8601"`
			} `json:"releases"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", pkg, err)
		}
		for _, v := range versions {
			for rel, files := range doc.Releases {
				if !sameVersion("PyPI", rel, v) {
					continue
				}
				for _, f := range files {
					t, err := time.Parse(time.RFC3339, f.Uploaded)
					if err == nil && (out[v].published.IsZero() || t.Before(out[v].published)) {
						out[v] = dating{published: t}
					}
				}
			}
		}
	case "Go":
		for _, v := range versions {
			if t, ok := r.goSeen[pkg+"@"+v]; ok {
				out[v] = dating{published: t}
				continue
			}
			_, status, err := r.get(ctx, up.URL+"/cached-only/"+escapeVersion(pkg)+"/@v/"+escapeVersion(v)+".info", "")
			if err != nil {
				return nil, err
			}
			if status == http.StatusOK {
				out[v] = dating{published: r.goSince, beforeWindow: true}
			}
		}
	}
	return out, nil
}

// The index keeps each version's first-served time; a version's .info Time is
// its commit or tag time, which can be far older.
func (r *holdLagRun) readGoIndex(ctx context.Context, base string, since, to time.Time, wanted map[string]bool) error {
	r.goSince = since
	r.goSeen = map[string]time.Time{}
	last := since
	for {
		body, status, err := r.get(ctx, fmt.Sprintf("%s/index?limit=%d&since=%s", base, indexPage, url.QueryEscape(last.UTC().Format(time.RFC3339Nano))), "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("%w: the module index answered %d", errRegistry, status)
		}
		n := 0
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			var e struct {
				Path, Version string
				Timestamp     time.Time
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			n++
			if e.Timestamp.After(last) {
				last = e.Timestamp
			}
			k := e.Path + "@" + e.Version
			if wanted[e.Path] {
				if t, ok := r.goSeen[k]; !ok || e.Timestamp.Before(t) {
					r.goSeen[k] = e.Timestamp
				}
			}
		}
		if n < indexPage || !last.Before(to) {
			return nil
		}
	}
}

type ecosystemReport struct {
	Ecosystem    string  `json:"ecosystem"`
	Hold         string  `json:"hold"`
	Entries      int     `json:"entries"`
	NoVersions   int     `json:"entriesNamingNoVersion"`
	Dated        int     `json:"dated"`
	Undated      int     `json:"undated"`
	AfterListing int     `json:"publishedAfterListing"`
	Unlisted     int     `json:"unlistedAtHold"`
	Share        float64 `json:"shareUnlistedAtHold"`
	Thin         bool    `json:"thin"`
	// 0 when no hold within SearchedDays reaches the target.
	ProposedDays int    `json:"proposedHoldDays"`
	SearchedDays int    `json:"searchedDays"`
	OutOfBand    bool   `json:"outOfBand"`
	Note         string `json:"note,omitempty"`
}

type holdLagReport struct {
	Month      string            `json:"month"`
	Generated  time.Time         `json:"generated"`
	Records    int               `json:"recordObjects"`
	Ecosystems []ecosystemReport `json:"ecosystems"`
}

// A lag known only as a lower bound is past every hold shorter than it, so it
// counts here like an exact one.
func lagShare(lags []time.Duration, hold time.Duration) (int, float64) {
	n := 0
	for _, l := range lags {
		if l > hold {
			n++
		}
	}
	if len(lags) == 0 {
		return 0, 0
	}
	return n, float64(n) / float64(len(lags))
}

func (r *holdLagRun) measure(up *Upstream, ls *monthListings, dates map[string]dating) ecosystemReport {
	rep := ecosystemReport{Ecosystem: up.Ecosystem, Hold: up.Hold.Duration.String(), Entries: ls.entries, NoVersions: ls.noVersions}
	var lags []time.Duration
	var shortestBound time.Duration
	for _, v := range ls.versions {
		d, ok := dates[v.pkg+"@"+v.version]
		switch {
		case !ok:
			rep.Undated++
		case d.published.After(v.listed):
			rep.AfterListing++
		default:
			l := v.listed.Sub(d.published)
			if d.beforeWindow && (shortestBound == 0 || l < shortestBound) {
				shortestBound = l
			}
			lags = append(lags, l)
		}
	}
	rep.Dated = len(lags)
	rep.Unlisted, rep.Share = lagShare(lags, up.Hold.Duration)
	rep.Thin = rep.Dated < r.cfg.MinDated
	rep.SearchedDays = r.cfg.MaxHoldDays
	if shortestBound > 0 {
		rep.SearchedDays = min(rep.SearchedDays, int((shortestBound-1)/(24*time.Hour)))
	}
	for d := 1; d <= rep.SearchedDays && rep.Dated > 0; d++ {
		if _, s := lagShare(lags, time.Duration(d)*24*time.Hour); s <= r.cfg.Target {
			rep.ProposedDays = d
			break
		}
	}
	rep.OutOfBand = !rep.Thin && (rep.Share > r.cfg.High || rep.Share < r.cfg.Low)
	return rep
}

type holdLagRun struct {
	cfg       *HoldLagConfig
	gw        *holdLagGateway
	client    *http.Client
	retryWait time.Duration
	goSince   time.Time
	goSeen    map[string]time.Time
}

func (r *holdLagRun) run(ctx context.Context, month time.Time, now time.Time) (*holdLagReport, error) {
	from := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	recorded, objects, err := recordedPublished(ctx, r.gw.records, r.gw.prefix, to.AddDate(0, 0, -32), to)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	rep := &holdLagReport{Month: from.Format("2006-01"), Generated: now, Records: objects}
	for _, up := range r.gw.upstreams {
		ls, err := readListings(ctx, r.client, r.gw.source, up.Ecosystem, from, to)
		if err != nil {
			return nil, fmt.Errorf("%s advisories: %w", up.Ecosystem, err)
		}
		byPkg := map[string][]string{}
		var pkgs []string
		for _, v := range ls.versions {
			if byPkg[v.pkg] == nil {
				pkgs = append(pkgs, v.pkg)
			}
			byPkg[v.pkg] = append(byPkg[v.pkg], v.version)
		}
		log.Printf("hold-lag %s: %s: %d malicious entries name %d versions of %d packages; dating them", rep.Month, up.Ecosystem, ls.entries, len(ls.versions), len(pkgs))
		if up.Ecosystem == "Go" && len(pkgs) > 0 {
			wanted := map[string]bool{}
			for _, p := range pkgs {
				wanted[p] = true
			}
			if err := r.readGoIndex(ctx, up.Index, from.Add(-r.cfg.GoWindow.Duration), to, wanted); err != nil {
				return nil, fmt.Errorf("Go index: %w", err)
			}
		}
		dates := map[string]dating{}
		for _, p := range pkgs {
			got, err := r.registryDates(ctx, up, p, byPkg[p])
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", up.Ecosystem, p, err)
			}
			for _, v := range byPkg[p] {
				if d, ok := got[v]; ok {
					dates[p+"@"+v] = d
				} else if t, ok := recorded[up.Ecosystem+"\x00"+packageKey(up.Ecosystem, p)+"@"+v]; ok {
					dates[p+"@"+v] = dating{published: t}
				}
			}
		}
		rep.Ecosystems = append(rep.Ecosystems, r.measure(up, ls, dates))
	}
	for i := range rep.Ecosystems {
		if e := &rep.Ecosystems[i]; e.Ecosystem == "PyPI" && e.Thin {
			for _, o := range rep.Ecosystems {
				if o.Ecosystem == "npm" && !o.Thin {
					e.Note = "thin, so PyPI's hold follows npm's"
				}
			}
		}
		if e := &rep.Ecosystems[i]; e.Thin && e.Note == "" {
			e.Note = "thin, so this month moves nothing"
		}
	}
	return rep, nil
}

func (r *holdLagRun) alerts(rep *holdLagReport) []alertmanagerAlert {
	var out []alertmanagerAlert
	for _, e := range rep.Ecosystems {
		if !e.OutOfBand {
			continue
		}
		proposal := fmt.Sprintf("no hold within %d days leaves %s or less", e.SearchedDays, pct(r.cfg.Target))
		if e.ProposedDays > 0 {
			proposal = fmt.Sprintf("%d days is the shortest hold that leaves %s or less", e.ProposedDays, pct(r.cfg.Target))
		}
		out = append(out, alertmanagerAlert{
			Labels: map[string]string{
				"alertname": "ViaMarisHoldLagOutOfBand",
				"severity":  "ticket",
				"ecosystem": e.Ecosystem,
				"month":     rep.Month,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s: %d of %d (%s) malicious versions listed in %s were still unlisted when the %s hold ended, outside %s to %s",
					e.Ecosystem, e.Unlisted, e.Dated, pct(e.Share), rep.Month, e.Hold, pct(r.cfg.Low), pct(r.cfg.High)),
				"description": proposal + ". Move the hold in the gateway's configuration by a reviewed change; the next month's run reads it.",
			},
		})
	}
	return out
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", math.Round(f*1000)/10) }

func (e ecosystemReport) String() string {
	proposal := fmt.Sprintf("no hold within %d days reaches the target", e.SearchedDays)
	if e.ProposedDays > 0 {
		proposal = fmt.Sprintf("the shortest hold reaching the target is %d days", e.ProposedDays)
	}
	band := "in band"
	if e.OutOfBand {
		band = "OUT OF BAND"
	}
	if e.Note != "" {
		band = e.Note
	}
	return fmt.Sprintf("%s hold %s: %d malicious entries (%d naming no version); %d versions dated, %d undated, %d published after their listing; %d (%s) unlisted when the hold ended; %s; %s",
		e.Ecosystem, e.Hold, e.Entries, e.NoVersions, e.Dated, e.Undated, e.AfterListing, e.Unlisted, pct(e.Share), proposal, band)
}

func previousMonth(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
}

func holdLagMain(args []string, client *http.Client) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: via-maris hold-lag <hold-lag.json> [YYYY-MM]")
	}
	cfg, err := loadHoldLagConfig(args[0])
	if err != nil {
		return err
	}
	gw, err := readHoldLagGateway(cfg.GatewayConfig, client)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	month := previousMonth(now)
	if len(args) == 2 {
		if month, err = time.Parse("2006-01", args[1]); err != nil {
			return fmt.Errorf("month %q: want YYYY-MM", args[1])
		}
	}
	r := &holdLagRun{cfg: cfg, gw: gw, client: client, retryWait: 5 * time.Second}
	ctx := context.Background()
	rep, err := r.run(ctx, month, now)
	if err != nil {
		return err
	}
	log.Printf("hold-lag %s: %d record objects read", rep.Month, rep.Records)
	for _, e := range rep.Ecosystems {
		log.Printf("hold-lag %s: %s", rep.Month, e)
	}
	if err := json.NewEncoder(os.Stdout).Encode(rep); err != nil {
		return err
	}
	alerts := r.alerts(rep)
	for i := range alerts {
		alerts[i].StartsAt, alerts[i].EndsAt = now, now.Add(cfg.AlertFor.Duration)
	}
	return postAlertmanager(ctx, client, cfg.Alertmanager, alerts)
}
