package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

type gateway struct {
	cfg        *Config
	client     *http.Client
	db         *advisoryDB
	inUse      *inUseSet
	records    *recorder
	goIdx      map[string]*goIndex
	ecosystems []string
	byName     *byName
}

func newGateway(cfg *Config, client *http.Client, recordLog io.Writer) (*gateway, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	g := &gateway{
		cfg:    cfg,
		client: client,
		db:     &advisoryDB{source: cfg.Advisories.Source, client: client, eco: map[string]*ecosystemData{}},
		inUse:  &inUseSet{store: newObjectStore(cfg.InUse.Store, client), object: cfg.InUse.Object},
		records: &recorder{
			log:    recordLog,
			store:  newObjectStore(cfg.Records.Store, client),
			prefix: cfg.Records.Prefix,
			host:   host,
		},
		goIdx: map[string]*goIndex{},
	}
	seen := map[string]bool{}
	for i := range cfg.Upstreams {
		up := &cfg.Upstreams[i]
		if up.checked() && !seen[up.Ecosystem] {
			seen[up.Ecosystem] = true
			g.ecosystems = append(g.ecosystems, up.Ecosystem)
		}
		if up.Ecosystem == "Go" {
			g.goIdx[up.Name] = newGoIndex(up, client)
		}
	}
	sort.Strings(g.ecosystems)
	if cfg.ByName != nil {
		g.byName = newByName(g, cfg.ByName)
	}
	return g, nil
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	for i := range g.cfg.Upstreams {
		up := &g.cfg.Upstreams[i]
		var h http.HandlerFunc
		switch up.Ecosystem {
		case "npm":
			h = func(w http.ResponseWriter, r *http.Request) { g.npm(w, r, up) }
		case "PyPI":
			h = func(w http.ResponseWriter, r *http.Request) { g.pypi(w, r, up) }
		case "Go":
			ix := g.goIdx[up.Name]
			h = func(w http.ResponseWriter, r *http.Request) { g.gomod(w, r, up, ix) }
		case "apt":
			h = func(w http.ResponseWriter, r *http.Request) { g.apt(w, r, up) }
		case "files":
			h = func(w http.ResponseWriter, r *http.Request) { g.pinned(w, r, up) }
		}
		mux.HandleFunc("/"+up.Name+"/", g.gated(up, h))
	}
	mux.HandleFunc("/healthz", g.healthz)
	mux.HandleFunc("/metrics", g.metrics)
	if g.byName == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			g.byName.connect(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// gated admits only reads, plus the POST of npm's audit, and refuses every
// request while decision records are failing to reach storage, so no
// decision is made that the record would not hold.
func (g *gateway) gated(up *Upstream, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !(up.Ecosystem == "npm" && r.Method == http.MethodPost) {
			http.Error(w, "via-maris: method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if reason := g.recordsBehind(); reason != "" {
			g.record(r, up, "request", r.URL.Path, "", verdict{false, reason})
			http.Error(w, "via-maris refused this request: "+reason, http.StatusServiceUnavailable)
			return
		}
		h(w, r)
	}
}

func (g *gateway) recordsBehind() string {
	if age := g.records.unshipped(); age > g.cfg.Records.MaxUnshipped.Duration {
		return fmt.Sprintf("decision records have not reached storage for %s, past the %s bound", age.Round(time.Second), g.cfg.Records.MaxUnshipped.Duration)
	}
	return ""
}

func (g *gateway) notReady() []string {
	var out []string
	for _, eco := range g.ecosystems {
		if g.advisoriesUnusable(eco) != "" {
			out = append(out, eco+" advisories")
		}
	}
	for name, ix := range g.goIdx {
		if ix.notReady() != "" {
			out = append(out, name+" index")
		}
	}
	if g.recordsBehind() != "" {
		out = append(out, "records")
	}
	if g.byName != nil {
		if _, err := g.byName.certs.current(); err != nil {
			out = append(out, "tls certificate")
		}
	}
	sort.Strings(out)
	return out
}

func (g *gateway) healthz(w http.ResponseWriter, r *http.Request) {
	if stale := g.notReady(); len(stale) > 0 {
		http.Error(w, "not ready: "+strings.Join(stale, ", ")+" (via-maris "+version+")", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintf(w, "ready (via-maris %s)\n", version)
}

func (g *gateway) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "via_maris_build_info{version=%q} 1\n", version)
	for _, eco := range g.ecosystems {
		age, ok := g.db.age(eco)
		if !ok {
			age = -time.Second
		}
		entries, mal := g.db.stats(eco)
		fmt.Fprintf(w, "via_maris_advisories_age_seconds{ecosystem=%q} %d\n", eco, int(age.Seconds()))
		fmt.Fprintf(w, "via_maris_advisories_entries{ecosystem=%q,kind=\"all\"} %d\n", eco, entries)
		fmt.Fprintf(w, "via_maris_advisories_entries{ecosystem=%q,kind=\"malicious\"} %d\n", eco, mal)
	}
	for name, ix := range g.goIdx {
		fmt.Fprintf(w, "via_maris_go_index_lag_seconds{upstream=%q} %d\n", name, int(ix.lag().Seconds()))
	}
	age, n, ok := g.inUse.age()
	if !ok {
		age = -time.Second
	}
	fmt.Fprintf(w, "via_maris_in_use_age_seconds %d\n", int(age.Seconds()))
	fmt.Fprintf(w, "via_maris_in_use_versions %d\n", n)
	fmt.Fprintf(w, "via_maris_records_unshipped_seconds %d\n", int(g.records.unshipped().Seconds()))
	fmt.Fprintf(w, "via_maris_decisions_total{served=\"true\"} %d\n", g.records.served.Load())
	fmt.Fprintf(w, "via_maris_decisions_total{served=\"false\"} %d\n", g.records.refused.Load())
	if g.byName != nil {
		leaf, ca := g.byName.certs.expiry()
		fmt.Fprintf(w, "via_maris_tls_expiry_timestamp_seconds{certificate=\"leaf\"} %d\n", unixOrZero(leaf))
		fmt.Fprintf(w, "via_maris_tls_expiry_timestamp_seconds{certificate=\"ca\"} %d\n", unixOrZero(ca))
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func every(ctx context.Context, interval time.Duration, f func(context.Context)) {
	for {
		run, cancel := context.WithTimeout(ctx, interval)
		f(run)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (g *gateway) start(ctx context.Context) {
	for _, eco := range g.ecosystems {
		go every(ctx, g.cfg.Advisories.Refresh.Duration, func(ctx context.Context) {
			start := time.Now()
			if err := g.db.load(ctx, eco); err != nil {
				log.Printf("advisories %s: %v", eco, err)
			} else {
				e, m := g.db.stats(eco)
				log.Printf("advisories %s: %d entries, %d malicious, loaded in %s", eco, e, m, time.Since(start).Round(time.Millisecond))
			}
			// The export is garbage once parsed; hand it back so the
			// resident size is the index alone.
			debug.FreeOSMemory()
		})
	}
	go every(ctx, g.cfg.InUse.Refresh.Duration, func(ctx context.Context) {
		if err := g.inUse.load(ctx); err != nil {
			log.Printf("in-use set: %v", err)
			return
		}
		_, n, _ := g.inUse.age()
		log.Printf("in-use set: %d versions", n)
	})
	for name, ix := range g.goIdx {
		go ix.run(ctx, name)
	}
}

func main() {
	client := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   32,
	}}
	if len(os.Args) == 3 && os.Args[1] == "recheck" {
		if err := recheckMain(os.Args[2], client); err != nil {
			log.Fatalf("recheck: %v", err)
		}
		return
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: via-maris <config.json>\n       via-maris recheck <recheck.json>")
		os.Exit(2)
	}
	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	g, err := newGateway(cfg, client, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	g.start(ctx)
	// The records loop outlives the server, so the decisions of requests
	// still in flight at shutdown are uploaded too.
	recordsCtx, stopRecords := context.WithCancel(context.Background())
	recordsDone := make(chan struct{})
	go func() {
		g.records.run(recordsCtx, cfg.Records.Interval.Duration)
		close(recordsDone)
	}()
	srv := &http.Server{Addr: cfg.Listen, Handler: g.handler(), ReadHeaderTimeout: 30 * time.Second}
	served := make(chan error, 2)
	go func() { served <- srv.ListenAndServe() }()
	log.Printf("via-maris %s listening on %s", version, cfg.Listen)
	if g.byName != nil {
		if _, err := g.byName.certs.current(); err != nil {
			log.Printf("tls certificate: %v; the by-name listener refuses handshakes until it loads", err)
		}
		ln, err := net.Listen("tcp", cfg.ByName.Listen)
		if err != nil {
			log.Fatal(err)
		}
		go func() { served <- g.byName.serveTLS(ln) }()
		log.Printf("serving %s and %s by name on %s", g.byName.indexHost, g.byName.filesHost, cfg.ByName.Listen)
	}
	select {
	case err := <-served:
		log.Fatal(err)
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		log.Printf("shutdown: %v", err)
	}
	if g.byName != nil {
		if err := g.byName.srv.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}
	stopRecords()
	<-recordsDone
}
