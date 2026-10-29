package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// What this counts and when it exits: docs/configuration.md, "The egress observer".

const egressMaxNames = 256

const allowAnyEgress = "reserved:io.cilium.policy.derived-from=allow-any-egress"

type EgressConfig struct {
	Listen   string      `json:"listen"`
	Relay    string      `json:"relay"`
	Policies []PolicyRef `json:"policies"`
}

type PolicyRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func loadEgressConfig(path string) (*EgressConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c EgressConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" || c.Relay == "" {
		return nil, fmt.Errorf("%s: listen and relay are required", path)
	}
	if len(c.Policies) == 0 {
		return nil, fmt.Errorf("%s: policies is empty", path)
	}
	seen := map[string]bool{}
	for _, p := range c.Policies {
		if p.Namespace == "" || p.Name == "" {
			return nil, fmt.Errorf("%s: each policy needs a namespace and a name", path)
		}
		// Flows are attributed to a policy by their pod's namespace.
		if seen[p.Namespace] {
			return nil, fmt.Errorf("%s: namespace %q has two policies", path, p.Namespace)
		}
		seen[p.Namespace] = true
	}
	return &c, nil
}

type cnp struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec *struct {
		EndpointSelector struct {
			MatchLabels      map[string]string `json:"matchLabels"`
			MatchExpressions []json.RawMessage `json:"matchExpressions"`
		} `json:"endpointSelector"`
		Egress []struct {
			ToPorts []struct {
				Rules *struct {
					DNS []dnsRule `json:"dns"`
				} `json:"rules"`
			} `json:"toPorts"`
		} `json:"egress"`
	} `json:"spec"`
	Specs []json.RawMessage `json:"specs"`
}

type dnsRule struct {
	MatchName    string `json:"matchName"`
	MatchPattern string `json:"matchPattern"`
}

type egressPolicy struct {
	selector map[string]string
	listed   func(string) bool
}

func compilePolicy(p cnp) (*egressPolicy, error) {
	if p.Spec == nil || len(p.Specs) > 0 {
		return nil, errors.New("only a policy with a single spec is read")
	}
	if len(p.Spec.EndpointSelector.MatchExpressions) > 0 {
		return nil, errors.New("an endpointSelector with matchExpressions is not read")
	}
	var rules []dnsRule
	for _, e := range p.Spec.Egress {
		for _, tp := range e.ToPorts {
			if tp.Rules != nil {
				rules = append(rules, tp.Rules.DNS...)
			}
		}
	}
	listed, err := dnsMatcher(rules)
	if err != nil {
		return nil, err
	}
	sel := map[string]string{}
	for k, v := range p.Spec.EndpointSelector.MatchLabels {
		sel[labelKeyWithoutSource(k)] = v
	}
	return &egressPolicy{selector: sel, listed: listed}, nil
}

// A Kubernetes label key holds no colon, so the first one ends the source.
func labelKeyWithoutSource(k string) string {
	if i := strings.IndexByte(k, ':'); i >= 0 {
		return k[i+1:]
	}
	return k
}

func (p *egressPolicy) selects(labels []string) bool {
	have := map[string]string{}
	for _, l := range labels {
		k, v, _ := strings.Cut(l, "=")
		have[labelKeyWithoutSource(k)] = v
	}
	for k, v := range p.selector {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

var (
	allNamesPattern = regexp.MustCompile(`^[*]{1,}[.]?$`)
	subdomainsStar  = regexp.MustCompile(`^[*]{2,}\[\.\]`)
	labelStar       = regexp.MustCompile(`[*]{1,}`)
)

// Ported from Cilium 1.19.0's pkg/fqdn/matchpattern, so a name counts as
// listed exactly when Cilium would allow it.
func dnsMatcher(rules []dnsRule) (func(string) bool, error) {
	const label = "[-a-zA-Z0-9_]"
	names := map[string]bool{}
	var res []*regexp.Regexp
	for _, d := range rules {
		switch {
		case d.MatchName != "":
			names[fqdn(d.MatchName)] = true
		case allNamesPattern.MatchString(d.MatchPattern):
			res = append(res, regexp.MustCompile(`(^(`+label+`+[.])+$)|(^[.]$)`))
		case d.MatchPattern != "":
			p := strings.ReplaceAll(fqdn(d.MatchPattern), ".", "[.]")
			p = subdomainsStar.ReplaceAllString(p, "("+label+"+([.]"+label+"+){0,})[.]")
			p = labelStar.ReplaceAllString(p, label+"*")
			re, err := regexp.Compile("^" + p + "$")
			if err != nil {
				return nil, fmt.Errorf("matchPattern %q: %w", d.MatchPattern, err)
			}
			res = append(res, re)
		}
	}
	return func(q string) bool {
		q = fqdn(q)
		if names[q] {
			return true
		}
		for _, re := range res {
			if re.MatchString(q) {
				return true
			}
		}
		return false
	}, nil
}

type unlistedCounter struct {
	mu     sync.Mutex
	counts map[egressKey]uint64
	names  map[[2]string]int
	lost   uint64
}

type egressKey struct{ namespace, kind, destination string }

var egressKinds = []string{"connection", "dns"}

func newUnlistedCounter(namespaces []string) *unlistedCounter {
	c := &unlistedCounter{counts: map[egressKey]uint64{}, names: map[[2]string]int{}}
	for _, ns := range namespaces {
		for _, kind := range egressKinds {
			c.counts[egressKey{ns, kind, "other"}] = 0
		}
	}
	return c
}

func (c *unlistedCounter) add(ns, kind, dst string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := egressKey{ns, kind, dst}
	if _, ok := c.counts[k]; !ok {
		if c.names[[2]string{ns, kind}] >= egressMaxNames {
			c.counts[egressKey{ns, kind, "other"}]++
			log.Printf("egress %s %s %s: past the %d-name cap, counted under other", ns, kind, dst, egressMaxNames)
			return
		}
		c.names[[2]string{ns, kind}]++
		log.Printf("egress %s %s %s: first unlisted event", ns, kind, dst)
	}
	c.counts[k]++
}

func (c *unlistedCounter) addLost(n uint64) {
	c.mu.Lock()
	c.lost += n
	c.mu.Unlock()
}

func (c *unlistedCounter) metrics(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	keys := make([]egressKey, 0, len(c.counts))
	for k := range c.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.namespace != b.namespace {
			return a.namespace < b.namespace
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.destination < b.destination
	})
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "via_maris_build_info{version=%q} 1\n", version)
	buf.WriteString("# TYPE via_maris_egress_unlisted_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(&buf, "via_maris_egress_unlisted_total{namespace=%q,kind=%q,destination=%q} %d\n", k.namespace, k.kind, k.destination, c.counts[k])
	}
	buf.WriteString("# TYPE via_maris_egress_lost_events_total counter\n")
	fmt.Fprintf(&buf, "via_maris_egress_lost_events_total %d\n", c.lost)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write(buf.Bytes())
}

type policySet struct {
	mu sync.RWMutex
	by map[string]*egressPolicy
}

func (s *policySet) get(ns string) *egressPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.by[ns]
}

func (s *policySet) set(ns string, p *egressPolicy) {
	s.mu.Lock()
	s.by[ns] = p
	s.mu.Unlock()
}

type kubeClient struct {
	base      string
	client    *http.Client
	tokenFile string
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

func inClusterKube() (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are unset; egress-observe runs in a pod")
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("service account ca.crt holds no certificate")
	}
	return &kubeClient{
		base:      "https://" + net.JoinHostPort(host, port),
		client:    &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
		tokenFile: serviceAccountDir + "/token",
	}, nil
}

func (k *kubeClient) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	// The kubelet rotates the projected token, so it is read for each request.
	if k.tokenFile != "" {
		tok, err := os.ReadFile(k.tokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, bytes.TrimSpace(b))
	}
	return resp, nil
}

func (k *kubeClient) readPolicy(ctx context.Context, ns, name string) (cnp, string, error) {
	resp, err := k.get(ctx, policyPath(ns), url.Values{"fieldSelector": {"metadata.name=" + name}})
	if err != nil {
		return cnp{}, "", err
	}
	defer resp.Body.Close()
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []cnp `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return cnp{}, "", fmt.Errorf("list %s/%s: %w", ns, name, err)
	}
	if len(list.Items) != 1 {
		return cnp{}, "", fmt.Errorf("policy %s/%s not found", ns, name)
	}
	return list.Items[0], list.Metadata.ResourceVersion, nil
}

func policyPath(ns string) string {
	return "/apis/cilium.io/v2/namespaces/" + url.PathEscape(ns) + "/ciliumnetworkpolicies"
}

func (k *kubeClient) watchPolicy(ctx context.Context, set *policySet, ns, name, rv string) error {
	for {
		resp, err := k.get(ctx, policyPath(ns), url.Values{
			"fieldSelector":   {"metadata.name=" + name},
			"watch":           {"1"},
			"resourceVersion": {rv},
		})
		if err != nil {
			return err
		}
		err = applyWatch(resp.Body, set, ns, name)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p, next, err := k.readPolicy(ctx, ns, name)
		if err != nil {
			return err
		}
		compiled, err := compilePolicy(p)
		if err != nil {
			return fmt.Errorf("policy %s/%s: %w", ns, name, err)
		}
		set.set(ns, compiled)
		rv = next
	}
}

func applyWatch(body io.Reader, set *policySet, ns, name string) error {
	dec := json.NewDecoder(body)
	for {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("watch %s/%s: %w", ns, name, err)
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			var p cnp
			if err := json.Unmarshal(ev.Object, &p); err != nil {
				return fmt.Errorf("watch %s/%s: %w", ns, name, err)
			}
			compiled, err := compilePolicy(p)
			if err != nil {
				return fmt.Errorf("policy %s/%s: %w", ns, name, err)
			}
			set.set(ns, compiled)
			log.Printf("policy %s/%s: read at resourceVersion %s", ns, name, p.Metadata.ResourceVersion)
		case "DELETED":
			return fmt.Errorf("policy %s/%s was deleted", ns, name)
		case "ERROR":
			// A 410 Gone for an expired resourceVersion: the caller lists again.
			var st struct {
				Code int `json:"code"`
			}
			json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return nil
			}
			return fmt.Errorf("watch %s/%s: %s", ns, name, ev.Object)
		}
	}
}

func pbTag(b []byte, num, wire int) []byte { return binary.AppendUvarint(b, uint64(num<<3|wire)) }

func pbBytes(b []byte, num int, v []byte) []byte {
	b = pbTag(b, num, 2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbVarint(b []byte, num int, v uint64) []byte {
	return binary.AppendUvarint(pbTag(b, num, 0), v)
}

// flowsRequest builds GetFlowsRequest{follow: true, whitelist: one
// FlowFilter{source_pod: ["<ns>/"], event_type: [{type: 5}, {type: 129}]} per
// namespace}: policy verdicts and L7 records from each namespace's pods.
func flowsRequest(namespaces []string) []byte {
	req := pbVarint(nil, 3, 1)
	for _, ns := range namespaces {
		ff := pbBytes(nil, 2, []byte(ns+"/"))
		for _, t := range []uint64{5, 129} {
			ff = pbBytes(ff, 6, pbVarint(nil, 1, t))
		}
		req = pbBytes(req, 6, ff)
	}
	return req
}

type pbMsg map[int][][]byte

func pbParse(b []byte) (pbMsg, error) {
	m := pbMsg{}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad tag")
		}
		b = b[n:]
		num := int(tag >> 3)
		switch tag & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			m[num] = append(m[num], binary.AppendUvarint(nil, v))
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("short fixed64")
			}
			m[num], b = append(m[num], b[:8]), b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("bad length")
			}
			m[num], b = append(m[num], b[n:n+int(l)]), b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("short fixed32")
			}
			m[num], b = append(m[num], b[:4]), b[4:]
		default:
			return nil, fmt.Errorf("wire type %d", tag&7)
		}
	}
	return m, nil
}

func (m pbMsg) uint(num int) uint64 {
	if v := m[num]; len(v) > 0 {
		x, _ := binary.Uvarint(v[0])
		return x
	}
	return 0
}

func (m pbMsg) str(num int) string {
	if v := m[num]; len(v) > 0 {
		return string(v[0])
	}
	return ""
}

func (m pbMsg) strs(num int) []string {
	out := make([]string, len(m[num]))
	for i, v := range m[num] {
		out[i] = string(v)
	}
	return out
}

func (m pbMsg) sub(num int) pbMsg {
	if v := m[num]; len(v) > 0 {
		s, _ := pbParse(v[0])
		return s
	}
	return pbMsg{}
}

// Encoded by hand so the binary stays on the standard library. Field numbers
// are from api/v1/flow/flow.proto and api/v1/observer/observer.proto at
// Cilium v1.19.0.
const (
	respFlow       = 1  // GetFlowsResponse.flow
	respLostEvents = 3  // GetFlowsResponse.lost_events
	lostNumEvents  = 2  // LostEvent.num_events_lost
	flowIP         = 5  // Flow.IP
	ipDestination  = 2  // IP.destination
	flowSource     = 8  // Flow.source
	endpointNS     = 3  // Endpoint.namespace
	endpointLabels = 4  // Endpoint.labels
	flowDestNames  = 14 // Flow.destination_names
	flowL7         = 15 // Flow.l7
	l7Type         = 1  // Layer7.type; REQUEST is 1
	l7DNS          = 100
	dnsQuery       = 1
	flowEventType  = 19 // Flow.event_type
	eventTypeType  = 1  // CiliumEventType.type
	flowDirection  = 22 // Flow.traffic_direction; EGRESS is 2
	flowEgressBy   = 21001
	policyLabels   = 3 // Policy.labels
)

func observeFlow(buf []byte, set *policySet, c *unlistedCounter) error {
	top, err := pbParse(buf)
	if err != nil {
		return fmt.Errorf("relay message: %w", err)
	}
	if le := top.sub(respLostEvents); len(le) > 0 {
		c.addLost(le.uint(lostNumEvents))
		return nil
	}
	if len(top[respFlow]) == 0 {
		return nil
	}
	f, err := pbParse(top[respFlow][0])
	if err != nil {
		return fmt.Errorf("relay flow: %w", err)
	}
	src := f.sub(flowSource)
	ns := src.str(endpointNS)
	p := set.get(ns)
	if p == nil || !p.selects(src.strs(endpointLabels)) {
		return nil
	}
	switch f.sub(flowEventType).uint(eventTypeType) {
	case 5:
		if f.uint(flowDirection) != 2 {
			return nil
		}
		for _, raw := range f[flowEgressBy] {
			pm, _ := pbParse(raw)
			for _, l := range pm.strs(policyLabels) {
				if l != allowAnyEgress {
					continue
				}
				dst := f.str(flowDestNames)
				if dst == "" {
					dst = f.sub(flowIP).str(ipDestination)
				}
				c.add(ns, "connection", dst)
				return nil
			}
		}
	case 129:
		l7 := f.sub(flowL7)
		if l7.uint(l7Type) != 1 || len(l7[l7DNS]) == 0 {
			return nil
		}
		if q := l7.sub(l7DNS).str(dnsQuery); q != "" && !p.listed(q) {
			c.add(ns, "dns", fqdn(q))
		}
	}
	return nil
}

func followRelay(ctx context.Context, client *http.Client, relay string, namespaces []string, set *policySet, c *unlistedCounter) error {
	body := flowsRequest(namespaces)
	frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(body)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+relay+"/observer.Observer/GetFlows", bytes.NewReader(append(frame, body...)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay: %s", resp.Status)
	}
	log.Printf("relay %s: following %s", relay, strings.Join(namespaces, ", "))
	br := bufio.NewReader(resp.Body)
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("relay stream ended: grpc-status %q %s", resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message"))
			}
			return fmt.Errorf("relay stream: %w", err)
		}
		if hdr[0] != 0 {
			return errors.New("relay sent a compressed message, which was not asked for")
		}
		buf := make([]byte, binary.BigEndian.Uint32(hdr[1:]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return fmt.Errorf("relay stream: %w", err)
		}
		if err := observeFlow(buf, set, c); err != nil {
			return err
		}
	}
}

func egressObserve(ctx context.Context, cfg *EgressConfig, kube *kubeClient, relayClient *http.Client, c *unlistedCounter) error {
	set := &policySet{by: map[string]*egressPolicy{}}
	rvs := map[string]string{}
	var namespaces []string
	for _, p := range cfg.Policies {
		raw, rv, err := kube.readPolicy(ctx, p.Namespace, p.Name)
		if err != nil {
			return err
		}
		compiled, err := compilePolicy(raw)
		if err != nil {
			return fmt.Errorf("policy %s/%s: %w", p.Namespace, p.Name, err)
		}
		set.set(p.Namespace, compiled)
		rvs[p.Namespace] = rv
		namespaces = append(namespaces, p.Namespace)
		log.Printf("policy %s/%s: read at resourceVersion %s", p.Namespace, p.Name, raw.Metadata.ResourceVersion)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, len(cfg.Policies)+1)
	for _, p := range cfg.Policies {
		go func() { done <- kube.watchPolicy(ctx, set, p.Namespace, p.Name, rvs[p.Namespace]) }()
	}
	go func() { done <- followRelay(ctx, relayClient, cfg.Relay, namespaces, set, c) }()
	return <-done
}

func egressObserveMain(path string) error {
	cfg, err := loadEgressConfig(path)
	if err != nil {
		return err
	}
	kube, err := inClusterKube()
	if err != nil {
		return err
	}
	var namespaces []string
	for _, p := range cfg.Policies {
		namespaces = append(namespaces, p.Namespace)
	}
	c := newUnlistedCounter(namespaces)
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", c.metrics)
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	log.Printf("via-maris %s egress-observe serving /metrics on %s", version, cfg.Listen)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	relayClient := &http.Client{Transport: &http.Transport{Protocols: &p}}
	observed := make(chan error, 1)
	go func() { observed <- egressObserve(ctx, cfg, kube, relayClient, c) }()
	select {
	case err := <-served:
		return err
	case err := <-observed:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}
