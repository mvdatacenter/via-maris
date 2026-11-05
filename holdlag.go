package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// docs/configuration.md, "The hold-lag report", states the rule these set.
const (
	holdLagTarget = 20
	holdLagLow    = 15
	holdLagHigh   = 25
	holdLagThin   = 100
)

type HoldLagConfig struct {
	Gateway      string   `json:"gateway"`
	GoWindow     Duration `json:"goWindow"`
	Alertmanager string   `json:"alertmanager"`
	AlertFor     Duration `json:"alertFor"`
}

func loadHoldLagConfig(path string) (*HoldLagConfig, *Config, error) {
	var c HoldLagConfig
	if err := decodeStrict(path, &c); err != nil {
		return nil, nil, err
	}
	if c.Gateway == "" {
		return nil, nil, fmt.Errorf("%s: gateway must name the gateway's configuration", path)
	}
	if c.GoWindow.Duration <= 0 {
		return nil, nil, fmt.Errorf("%s: goWindow must be positive", path)
	}
	if !httpURL(c.Alertmanager) || c.AlertFor.Duration <= 0 {
		return nil, nil, fmt.Errorf("%s: alertmanager must be an http(s) URL without a trailing slash, and alertFor positive", path)
	}
	var gw Config
	if err := decodeStrict(c.Gateway, &gw); err != nil {
		return nil, nil, err
	}
	if !httpURL(gw.Advisories.Source) {
		return nil, nil, fmt.Errorf("%s: advisories.source must be an http(s) URL without a trailing slash", c.Gateway)
	}
	if err := gw.Records.Store.validate("records"); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", c.Gateway, err)
	}
	seen := map[string]bool{}
	holds := map[string]time.Duration{}
	for i := range gw.Upstreams {
		up := &gw.Upstreams[i]
		if err := up.validate(seen); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", c.Gateway, err)
		}
		if !up.checked() {
			continue
		}
		if h, ok := holds[up.Ecosystem]; ok && h != up.Hold.Duration {
			return nil, nil, fmt.Errorf("%s: the %s upstreams hold for %s and %s, so the report has no one %s hold to measure", c.Gateway, up.Ecosystem, h, up.Hold.Duration, up.Ecosystem)
		}
		holds[up.Ecosystem] = up.Hold.Duration
	}
	if len(holds) == 0 {
		return nil, nil, fmt.Errorf("%s: no upstream is checked against advisories", c.Gateway)
	}
	if h, ok := holds["Go"]; ok && c.GoWindow.Duration <= h {
		return nil, nil, fmt.Errorf("%s: goWindow %s must exceed the Go hold of %s", path, c.GoWindow.Duration, h)
	}
	return &c, &gw, nil
}

type listedVersion struct {
	pkg     string
	version string
	listed  time.Time
}

type dating struct {
	at         time.Time
	lowerBound bool
	from       string
}

type HoldLagEcosystem struct {
	Ecosystem               string         `json:"ecosystem"`
	Hold                    string         `json:"hold"`
	Entries                 int            `json:"entries"`
	EntriesNamingNoVersions int            `json:"entriesNamingNoVersions"`
	Versions                int            `json:"versions"`
	Dated                   int            `json:"dated"`
	Undated                 int            `json:"undated"`
	PublishedAfterListing   int            `json:"publishedAfterListing"`
	DatedFrom               map[string]int `json:"datedFrom"`
	UnlistedAtHold          int            `json:"unlistedAtHold"`
	Share                   float64        `json:"share"`
	Thin                    bool           `json:"thin"`
	OutOfBand               bool           `json:"outOfBand"`
	ShortestHold            string         `json:"shortestHold,omitempty"`
	Note                    string         `json:"note,omitempty"`
}

type HoldLagReport struct {
	Month      string             `json:"month"`
	Generated  time.Time          `json:"generated"`
	Ecosystems []HoldLagEcosystem `json:"ecosystems"`
}

type holdLagRun struct {
	cfg    *HoldLagConfig
	gw     *Config
	g      *gateway
	client *http.Client
	store  *objectStore
	now    time.Time
}

func newHoldLagRun(cfg *HoldLagConfig, gw *Config, client *http.Client, now time.Time) *holdLagRun {
	return &holdLagRun{
		cfg:    cfg,
		gw:     gw,
		g:      &gateway{cfg: gw, client: client, poms: &pomDates{at: map[string]time.Time{}}},
		client: client,
		store:  newObjectStore(gw.Records.Store, client),
		now:    now,
	}
}

func monthBounds(month string, now time.Time) (time.Time, time.Time, error) {
	if month == "" {
		n := now.UTC()
		start := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
		return start, start.AddDate(0, 1, 0), nil
	}
	start, err := time.Parse("2006-01", month)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("month %q is not YYYY-MM", month)
	}
	return start, start.AddDate(0, 1, 0), nil
}

func (r *holdLagRun) upstreams(eco string) []*Upstream {
	var out []*Upstream
	for i := range r.gw.Upstreams {
		if r.gw.Upstreams[i].Ecosystem == eco {
			out = append(out, &r.gw.Upstreams[i])
		}
	}
	return out
}

func (r *holdLagRun) ecosystems() []string {
	seen := map[string]bool{}
	var out []string
	for _, up := range r.gw.Upstreams {
		if up.checked() && !seen[up.Ecosystem] {
			seen[up.Ecosystem] = true
			out = append(out, up.Ecosystem)
		}
	}
	sort.Strings(out)
	return out
}

func (r *holdLagRun) run(ctx context.Context, month string) (*HoldLagReport, error) {
	start, end, err := monthBounds(month, r.now)
	if err != nil {
		return nil, err
	}
	if !end.Before(r.now) {
		return nil, fmt.Errorf("%s has not ended, so its listings are not all in", start.Format("2006-01"))
	}
	report := &HoldLagReport{Month: start.Format("2006-01"), Generated: r.now.UTC()}
	listed := map[string][]listedVersion{}
	for _, eco := range r.ecosystems() {
		e := HoldLagEcosystem{Ecosystem: eco, Hold: r.upstreams(eco)[0].Hold.Duration.String(), DatedFrom: map[string]int{}}
		vs, err := r.listings(ctx, eco, start, end, &e)
		if err != nil {
			return nil, fmt.Errorf("advisories %s: %w", eco, err)
		}
		listed[eco] = vs
		report.Ecosystems = append(report.Ecosystems, e)
	}
	recorded, err := r.recordedTimes(ctx, listed)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	for i := range report.Ecosystems {
		e := &report.Ecosystems[i]
		dates, err := r.date(ctx, e.Ecosystem, start, listed[e.Ecosystem], recorded)
		if err != nil {
			return nil, fmt.Errorf("dating %s: %w", e.Ecosystem, err)
		}
		measure(e, r.upstreams(e.Ecosystem)[0].Hold.Duration, listed[e.Ecosystem], dates)
	}
	follow(report)
	for _, e := range report.Ecosystems {
		log.Printf("hold-lag %s %s: %d entries (%d naming no versions), %d versions, %d dated %v, %d undated, %d published after the listing; %d (%.1f%%) unlisted when the %s hold ended%s",
			report.Month, e.Ecosystem, e.Entries, e.EntriesNamingNoVersions, e.Versions, e.Dated, e.DatedFrom, e.Undated, e.PublishedAfterListing, e.UnlistedAtHold, e.Share*100, e.Hold, noteSuffix(e.Note))
	}
	if err := sendAlerts(ctx, r.client, r.cfg.Alertmanager, outOfBandAlerts(report, r.cfg, r.now)); err != nil {
		return nil, err
	}
	return report, nil
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return "; " + note
}

func (r *holdLagRun) listings(ctx context.Context, eco string, start, end time.Time, e *HoldLagEcosystem) ([]listedVersion, error) {
	earliest := map[[2]string]time.Time{}
	var parseErr error
	err := readExport(ctx, r.client, r.gw.Advisories.Source, eco, func(entry *osvEntry) {
		if !strings.HasPrefix(entry.ID, "MAL-") || parseErr != nil {
			return
		}
		at, err := time.Parse(time.RFC3339Nano, entry.Published)
		if err != nil {
			parseErr = fmt.Errorf("%s: published %q: %w", entry.ID, entry.Published, err)
			return
		}
		if at.Before(start) || !at.Before(end) {
			return
		}
		named := false
		for _, a := range entry.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			for _, v := range a.Versions {
				named = true
				k := [2]string{packageKey(eco, a.Package.Name), v}
				if t, ok := earliest[k]; !ok || at.Before(t) {
					earliest[k] = at
				}
			}
		}
		e.Entries++
		if !named {
			e.EntriesNamingNoVersions++
		}
	})
	if err == nil {
		err = parseErr
	}
	if err != nil {
		return nil, err
	}
	out := make([]listedVersion, 0, len(earliest))
	for k, at := range earliest {
		out = append(out, listedVersion{pkg: k[0], version: k[1], listed: at})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].pkg+"@"+out[i].version < out[j].pkg+"@"+out[j].version
	})
	e.Versions = len(out)
	return out, nil
}

func recordKey(eco, pkg, version string) string {
	return eco + "\x00" + packageKey(eco, pkg) + "\x00" + version
}

// goVersions are the spellings a Go version may take: OSV writes some
// without the leading v the proxy and the records carry.
func goVersions(v string) []string {
	if strings.HasPrefix(v, "v") {
		return []string{v}
	}
	return []string{v, "v" + v}
}

func (r *holdLagRun) recordedTimes(ctx context.Context, listed map[string][]listedVersion) (map[string]time.Time, error) {
	want := map[string]bool{}
	for eco, vs := range listed {
		for _, v := range vs {
			for _, s := range goVersions(v.version) {
				want[recordKey(eco, v.pkg, s)] = true
			}
		}
	}
	out := map[string]time.Time{}
	if len(want) == 0 {
		return out, nil
	}
	keys, err := r.store.list(ctx, r.gw.Records.Prefix, "")
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := readRecordedTimes(ctx, r.store, key, want, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readRecordedTimes(ctx context.Context, store *objectStore, key string, want map[string]bool, out map[string]time.Time) error {
	body, err := store.get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if rec.Published == "" {
			continue
		}
		k := recordKey(rec.Ecosystem, rec.Package, rec.Version)
		if !want[k] {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rec.Published)
		if err != nil {
			return fmt.Errorf("%s: published %q: %w", key, rec.Published, err)
		}
		if t, ok := out[k]; !ok || at.Before(t) {
			out[k] = at
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func (r *holdLagRun) date(ctx context.Context, eco string, start time.Time, vs []listedVersion, recorded map[string]time.Time) (map[int]dating, error) {
	out := map[int]dating{}
	fromRecord := func(i int, v listedVersion) bool {
		for _, s := range goVersions(v.version) {
			if at, ok := recorded[recordKey(eco, v.pkg, s)]; ok {
				out[i] = dating{at: at, from: "record"}
				return true
			}
		}
		return false
	}
	switch eco {
	case "Go":
		return out, r.dateGo(ctx, start, vs, out, fromRecord)
	case "npm", "PyPI", "Maven":
	default:
		return nil, fmt.Errorf("no registry dating for %s", eco)
	}
	cache := map[string]any{}
	for i, v := range vs {
		at, err := r.registryTime(ctx, eco, v, cache)
		if err != nil {
			return nil, err
		}
		if !at.IsZero() {
			out[i] = dating{at: at, from: "registry"}
			continue
		}
		fromRecord(i, v)
	}
	return out, nil
}

func (r *holdLagRun) registryTime(ctx context.Context, eco string, v listedVersion, cache map[string]any) (time.Time, error) {
	for _, up := range r.upstreams(eco) {
		key := up.Name + "\x00" + v.pkg
		switch eco {
		case "npm":
			doc, ok := cache[key].(map[string]any)
			if _, seen := cache[key]; !seen {
				d, status, err := r.g.packument(ctx, up, v.pkg)
				if err != nil {
					return time.Time{}, err
				}
				if status != http.StatusOK && status != http.StatusNotFound {
					return time.Time{}, fmt.Errorf("%s: %s answered %d", v.pkg, up.URL, status)
				}
				cache[key], doc, ok = d, d, d != nil
			}
			if ok {
				if at := npmPublished(doc, v.version); !at.IsZero() {
					return at, nil
				}
			}
		case "PyPI":
			doc, ok := cache[key].(map[string]any)
			if _, seen := cache[key]; !seen {
				d, status, err := r.g.simplePage(ctx, up, v.pkg)
				if err != nil {
					return time.Time{}, err
				}
				if status != http.StatusOK && status != http.StatusNotFound {
					return time.Time{}, fmt.Errorf("%s: %s answered %d", v.pkg, up.URL, status)
				}
				cache[key], doc, ok = d, d, d != nil
			}
			if ok {
				if at := pypiUploaded(doc, v.pkg, v.version); !at.IsZero() {
					return at, nil
				}
			}
		case "Maven":
			group, artifact, ok := strings.Cut(v.pkg, ":")
			if !ok {
				return time.Time{}, nil
			}
			ref := mavenRef{dir: strings.ReplaceAll(group, ".", "/") + "/" + artifact, group: group, artifact: artifact}
			at, status, err := r.g.pomPublished(ctx, up, ref, v.version)
			if err != nil {
				return time.Time{}, err
			}
			if status == http.StatusOK && !at.IsZero() {
				return at, nil
			}
		}
	}
	return time.Time{}, nil
}

func pypiUploaded(doc map[string]any, project, version string) time.Time {
	files, _ := doc["files"].([]any)
	var first time.Time
	for _, f := range files {
		m, _ := f.(map[string]any)
		p, v, ok := pypiFilename(fileField(m, "filename"))
		if !ok || p != project || !sameVersion("PyPI", v, version) {
			continue
		}
		at, err := time.Parse(time.RFC3339, fileField(m, "upload-time"))
		if err == nil && (first.IsZero() || at.Before(first)) {
			first = at
		}
	}
	return first
}

func (r *holdLagRun) dateGo(ctx context.Context, start time.Time, vs []listedVersion, out map[int]dating, fromRecord func(int, listedVersion) bool) error {
	if len(vs) == 0 {
		return nil
	}
	var up *Upstream
	for _, u := range r.upstreams("Go") {
		if u.Index != "" {
			up = u
			break
		}
	}
	if up == nil {
		return errors.New("no Go upstream names an index")
	}
	keep := map[string]bool{}
	for _, v := range vs {
		for _, s := range goVersions(v.version) {
			keep[v.pkg+"@"+s] = true
		}
	}
	from := start.Add(-r.cfg.GoWindow.Duration)
	ix := &goIndex{base: up.Index, client: r.client, seen: map[string]time.Time{}, want: keep, since: from, last: from}
	if err := ix.read(ctx); err != nil {
		return err
	}
	for i, v := range vs {
		dated := false
		for _, s := range goVersions(v.version) {
			if at, ok := ix.firstSeen(v.pkg, s); ok {
				out[i] = dating{at: at, from: "index"}
				dated = true
				break
			}
		}
		if dated || fromRecord(i, v) {
			continue
		}
		held, err := r.goHeld(ctx, up, v)
		if err != nil {
			return err
		}
		if held {
			out[i] = dating{at: from, lowerBound: true, from: "before the index window"}
		}
	}
	return nil
}

func (r *holdLagRun) goHeld(ctx context.Context, up *Upstream, v listedVersion) (bool, error) {
	ver := goVersions(v.version)
	resp, err := r.g.fetch(ctx, up.URL+"/cached-only/"+escapeVersion(v.pkg)+"/@v/"+escapeVersion(ver[len(ver)-1])+".info", "")
	if err != nil {
		return false, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	}
	return false, fmt.Errorf("%s@%s: cached-only answered %s", v.pkg, v.version, resp.Status)
}

type lag struct {
	d          time.Duration
	lowerBound bool
}

func measure(e *HoldLagEcosystem, hold time.Duration, vs []listedVersion, dates map[int]dating) {
	var lags []lag
	for i, v := range vs {
		d, ok := dates[i]
		if !ok {
			e.Undated++
			continue
		}
		if d.at.After(v.listed) {
			e.PublishedAfterListing++
			continue
		}
		e.DatedFrom[d.from]++
		lags = append(lags, lag{v.listed.Sub(d.at), d.lowerBound})
	}
	e.Dated = len(lags)
	e.UnlistedAtHold = unlistedAt(lags, hold)
	if e.Dated > 0 {
		e.Share = float64(e.UnlistedAtHold) / float64(e.Dated)
	}
	e.Thin = e.Dated < holdLagThin
	e.OutOfBand = !e.Thin && (e.UnlistedAtHold*100 > holdLagHigh*e.Dated || e.UnlistedAtHold*100 < holdLagLow*e.Dated)
	if days, ok := shortestHoldDays(lags); ok {
		e.ShortestHold = (time.Duration(days) * 24 * time.Hour).String()
	} else if e.Dated > 0 {
		e.Note = fmt.Sprintf("more than %d%% of the dated versions were listed later than the index window reaches, so no hold inside it is named", holdLagTarget)
	}
}

func unlistedAt(lags []lag, hold time.Duration) int {
	n := 0
	for _, l := range lags {
		if l.d > hold {
			n++
		}
	}
	return n
}

func shortestHoldDays(lags []lag) (int, bool) {
	if len(lags) == 0 {
		return 0, false
	}
	limit := time.Duration(1<<63 - 1)
	for _, l := range lags {
		if l.lowerBound {
			limit = min(limit, l.d)
		}
	}
	// A hold past the longest lag leaves none unlisted, so the loop ends.
	for days := 1; ; days++ {
		h := time.Duration(days) * 24 * time.Hour
		if h >= limit {
			return 0, false
		}
		if unlistedAt(lags, h)*100 <= holdLagTarget*len(lags) {
			return days, true
		}
	}
}

func follow(report *HoldLagReport) {
	for i := range report.Ecosystems {
		e := &report.Ecosystems[i]
		var note string
		switch {
		case e.Thin && (e.Ecosystem == "PyPI" || e.Ecosystem == "Maven"):
			note = fmt.Sprintf("thin, with fewer than %d dated versions, so this month moves nothing and the hold follows npm's", holdLagThin)
		case e.Thin:
			note = fmt.Sprintf("thin, with fewer than %d dated versions, so this month moves nothing", holdLagThin)
		case e.Ecosystem == "Go" && e.ShortestHold != "":
			shortest, _ := time.ParseDuration(e.ShortestHold)
			if hold, _ := time.ParseDuration(e.Hold); shortest > hold {
				note = "a longer Go hold lengthens the index window the gateway reads before /healthz reports ready, so measure that start-up before moving it"
			}
		}
		if note != "" && e.Note != "" {
			note += "; " + e.Note
		} else if note == "" {
			note = e.Note
		}
		e.Note = note
	}
}

func outOfBandAlerts(report *HoldLagReport, cfg *HoldLagConfig, now time.Time) []amAlert {
	var out []amAlert
	for _, e := range report.Ecosystems {
		if !e.OutOfBand {
			continue
		}
		suggestion := fmt.Sprintf("No whole-day hold inside the index window leaves %d%% or less unlisted.", holdLagTarget)
		if e.ShortestHold != "" {
			suggestion = fmt.Sprintf("The shortest whole-day hold leaving %d%% or less unlisted is %s.", holdLagTarget, e.ShortestHold)
		}
		out = append(out, amAlert{
			Labels: map[string]string{
				"alertname": "ViaMarisHoldLagOutOfBand",
				"severity":  "ticket",
				"ecosystem": e.Ecosystem,
				"month":     report.Month,
			},
			Annotations: map[string]string{
				"summary": fmt.Sprintf("%s: %d of the %d malicious versions dated in %s (%.1f%%) were still unlisted when the %s hold ended, outside %d%% to %d%%",
					e.Ecosystem, e.UnlistedAtHold, e.Dated, report.Month, e.Share*100, e.Hold, holdLagLow, holdLagHigh),
				"description": suggestion + " Move the hold in " + cfg.Gateway + " by a reviewed change; the next month's run reads it.",
			},
			StartsAt: now,
			EndsAt:   now.Add(cfg.AlertFor.Duration),
		})
	}
	return out
}

func holdLagMain(args []string, client *http.Client) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: via-maris hold-lag <hold-lag.json> [YYYY-MM]")
	}
	cfg, gw, err := loadHoldLagConfig(args[0])
	if err != nil {
		return err
	}
	month := ""
	if len(args) == 2 {
		month = args[1]
	}
	report, err := newHoldLagRun(cfg, gw, client, time.Now()).run(context.Background(), month)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
