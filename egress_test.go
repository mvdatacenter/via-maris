package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDNSMatcherFollowsCiliumPatterns(t *testing.T) {
	listed, err := dnsMatcher([]dnsRule{
		{MatchPattern: "**.cluster.local"},
		{MatchPattern: "**.lan"},
		{MatchName: "GitHub.com"},
		{MatchPattern: "*.actions.githubusercontent.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]bool{
		"github.com":                             true,
		"github.com.":                            true,
		"GITHUB.COM":                             true,
		"api.github.com.":                        false,
		"via-maris.via-maris.svc.cluster.local.": true,
		"cluster.local.":                         false,
		"pypi.org.lan.":                          true,
		"pypi.org.":                              false,
		"pipelines.actions.githubusercontent.com.":   true,
		"a.pipelines.actions.githubusercontent.com.": false,
		"actions.githubusercontent.com.":             false,
		"registry.npmjs.org.cluster.local.evil.com.": false,
	} {
		if got := listed(q); got != want {
			t.Errorf("listed(%q) = %v, want %v", q, got, want)
		}
	}
	all, err := dnsMatcher([]dnsRule{{MatchPattern: "*"}})
	if err != nil {
		t.Fatal(err)
	}
	if !all("pypi.org.") || !all("a.b.c.") {
		t.Error(`a lone "*" matches every name`)
	}
	none, _ := dnsMatcher(nil)
	if none("github.com") {
		t.Error("no rule lists no name")
	}
}

const testPolicy = `{
  "metadata": {"name": "workspace-egress", "namespace": "workspace", "resourceVersion": "%s"},
  "spec": {
    "endpointSelector": {"matchLabels": {"app": "workspace"}},
    "egress": [
      {"toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}],
                    "rules": {"dns": [{"matchPattern": "**.cluster.local"}, {"matchName": "github.com"}%s]}}]},
      {"toEntities": ["cluster"]}
    ]
  }
}`

func policyJSON(rv string, extra ...string) string {
	var more string
	for _, n := range extra {
		more += fmt.Sprintf(`, {"matchName": %q}`, n)
	}
	return fmt.Sprintf(testPolicy, rv, more)
}

func compiled(t *testing.T, js string) *egressPolicy {
	t.Helper()
	var p cnp
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatal(err)
	}
	c, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCompilePolicyReadsSelectorAndDNSRules(t *testing.T) {
	p := compiled(t, policyJSON("1"))
	if !p.listed("github.com.") || !p.listed("kube-dns.kube-system.svc.cluster.local.") || p.listed("pypi.org.") {
		t.Error("DNS rules not read from egress[].toPorts[].rules.dns")
	}
	if !p.selects([]string{"k8s:app=workspace", "k8s:io.kubernetes.pod.namespace=workspace"}) {
		t.Error("the workspace pod is selected")
	}
	if p.selects([]string{"k8s:app=reclaim"}) || p.selects(nil) {
		t.Error("a pod without app=workspace is not selected")
	}

	for name, js := range map[string]string{
		"specs":            `{"specs": [{}]}`,
		"no spec":          `{}`,
		"matchExpressions": `{"spec": {"endpointSelector": {"matchExpressions": [{"key": "app", "operator": "Exists"}]}}}`,
	} {
		var p cnp
		json.Unmarshal([]byte(js), &p)
		if _, err := compilePolicy(p); err == nil {
			t.Errorf("%s: compiled a policy the observer cannot read faithfully", name)
		}
	}
}

func TestSelectorKeysCompareWithoutTheirSource(t *testing.T) {
	p := compiled(t, strings.Replace(policyJSON("1"), `"app": "workspace"`, `"k8s:actions.github.com/scale-set-name": "runner-set"`, 1))
	if !p.selects([]string{"k8s:actions.github.com/scale-set-name=runner-set"}) {
		t.Error("k8s:-prefixed selector key matches the pod's k8s: label")
	}
	if p.selects([]string{"k8s:actions.github.com/scale-set-name=other"}) {
		t.Error("a different value is not selected")
	}
}

func metricsText(c *unlistedCounter) string {
	rec := httptest.NewRecorder()
	c.metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestCounterShowsEachNamespaceBeforeItsFirstEvent(t *testing.T) {
	out := metricsText(newUnlistedCounter([]string{"arc-runners", "workspace"}))
	for _, want := range []string{
		`via_maris_egress_unlisted_total{policy_namespace="arc-runners",kind="connection",destination="other"} 0`,
		`via_maris_egress_unlisted_total{policy_namespace="arc-runners",kind="dns",destination="other"} 0`,
		`via_maris_egress_unlisted_total{policy_namespace="workspace",kind="connection",destination="other"} 0`,
		`via_maris_egress_unlisted_total{policy_namespace="workspace",kind="dns",destination="other"} 0`,
		"via_maris_egress_lost_events_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s:\n%s", want, out)
		}
	}
}

func TestCounterFoldsNamesPastTheCapUnderOther(t *testing.T) {
	c := newUnlistedCounter([]string{"workspace"})
	for i := 0; i < egressMaxNames; i++ {
		c.add("workspace", "dns", fmt.Sprintf("n%d.example.", i))
	}
	c.add("workspace", "dns", "n0.example.")
	c.add("workspace", "dns", "past.example.")
	c.add("workspace", "dns", "past.example.")
	c.add("workspace", "connection", "pypi.org")
	c.addLost(3)
	out := metricsText(c)
	for _, want := range []string{
		`{policy_namespace="workspace",kind="dns",destination="n0.example."} 2`,
		`{policy_namespace="workspace",kind="dns",destination="other"} 2`,
		`{policy_namespace="workspace",kind="connection",destination="pypi.org"} 1`,
		`{policy_namespace="workspace",kind="connection",destination="other"} 0`,
		"via_maris_egress_lost_events_total 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(out, "past.example.") {
		t.Error("a name past the cap has a series of its own")
	}
	if n := strings.Count(out, `namespace="workspace",kind="dns"`); n != egressMaxNames+1 {
		t.Errorf("%d dns series, want %d names and other", n, egressMaxNames+1)
	}
}

func pbString(b []byte, num int, s string) []byte { return pbBytes(b, num, []byte(s)) }

type testFlow struct {
	ns        string
	labels    []string
	eventType uint64
	direction uint64
	dnsQuery  string
	dnsType   uint64
	destName  string
	destIP    string
	allowedBy [][]string
}

func (tf testFlow) response() []byte {
	src := pbString(nil, endpointNS, tf.ns)
	for _, l := range tf.labels {
		src = pbString(src, endpointLabels, l)
	}
	f := pbBytes(nil, flowSource, src)
	f = pbBytes(f, flowEventType, pbVarint(nil, eventTypeType, tf.eventType))
	if tf.direction != 0 {
		f = pbVarint(f, flowDirection, tf.direction)
	}
	if tf.destIP != "" {
		f = pbBytes(f, flowIP, pbString(nil, ipDestination, tf.destIP))
	}
	if tf.destName != "" {
		f = pbString(f, flowDestNames, tf.destName)
	}
	if tf.dnsQuery != "" {
		l7 := pbVarint(nil, l7Type, tf.dnsType)
		l7 = pbBytes(l7, l7DNS, pbString(nil, dnsQuery, tf.dnsQuery))
		f = pbBytes(f, flowL7, l7)
	}
	for _, labels := range tf.allowedBy {
		var pol []byte
		for _, l := range labels {
			pol = pbString(pol, policyLabels, l)
		}
		f = pbBytes(f, flowEgressBy, pol)
	}
	return pbBytes(nil, respFlow, f)
}

func lostEvents(n uint64) []byte {
	return pbBytes(nil, respLostEvents, pbVarint(nil, lostNumEvents, n))
}

var workspacePod = []string{"k8s:app=workspace", "k8s:io.kubernetes.pod.namespace=workspace"}

func dnsRequest(q string) testFlow {
	return testFlow{ns: "workspace", labels: workspacePod, eventType: 129, dnsType: 1, dnsQuery: q}
}

func policyVerdict(dst, ip string, allowedBy ...[]string) testFlow {
	return testFlow{ns: "workspace", labels: workspacePod, eventType: 5, direction: 2, destName: dst, destIP: ip, allowedBy: allowedBy}
}

func TestObserveFlowCountsWhatEnforcementWouldRefuse(t *testing.T) {
	set := &policySet{by: map[string]*egressPolicy{"workspace": compiled(t, policyJSON("1"))}}
	c := newUnlistedCounter([]string{"workspace"})
	anyEgress := []string{allowAnyEgress}
	byPolicy := []string{"k8s:io.cilium.k8s.policy.name=workspace-egress"}

	for _, tf := range []testFlow{
		// Counted: what enforcement would refuse.
		dnsRequest("pypi.org."),
		dnsRequest("pypi.org."),
		dnsRequest("PyPI.org"),
		dnsRequest("pypi.org.lan."),
		policyVerdict("pypi.org", "151.101.0.223", anyEgress),
		policyVerdict("", "151.101.0.223", anyEgress),
		// Listed, or not what enforcement refuses.
		dnsRequest("github.com."),
		dnsRequest("via-maris.via-maris.svc.cluster.local."),
		{ns: "workspace", labels: workspacePod, eventType: 129, dnsType: 2, dnsQuery: "pypi.org."},
		policyVerdict("github.com", "140.82.121.4", byPolicy),
		{ns: "workspace", labels: workspacePod, eventType: 5, direction: 1, destName: "pypi.org", allowedBy: [][]string{anyEgress}},
		// Not a pod the policy selects, or not a namespace observed.
		{ns: "workspace", labels: []string{"k8s:app=reclaim"}, eventType: 129, dnsType: 1, dnsQuery: "pypi.org."},
		{ns: "kube-system", labels: workspacePod, eventType: 129, dnsType: 1, dnsQuery: "pypi.org."},
	} {
		if err := observeFlow(tf.response(), set, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := observeFlow(lostEvents(7), set, c); err != nil {
		t.Fatal(err)
	}
	if err := observeFlow([]byte{0xff}, set, c); err == nil {
		t.Error("a relay message that does not parse was skipped")
	}
	if err := observeFlow(pbBytes(nil, respFlow, []byte{0x0a, 0x05}), set, c); err == nil {
		t.Error("a flow that does not parse was skipped")
	}

	out := metricsText(c)
	for _, want := range []string{
		`{policy_namespace="workspace",kind="dns",destination="pypi.org."} 3`,
		`{policy_namespace="workspace",kind="dns",destination="pypi.org.lan."} 1`,
		`{policy_namespace="workspace",kind="connection",destination="pypi.org"} 1`,
		`{policy_namespace="workspace",kind="connection",destination="151.101.0.223"} 1`,
		"via_maris_egress_lost_events_total 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "via_maris_egress_unlisted_total{"); n != 6 {
		t.Errorf("%d unlisted series, want 4 and the two under other:\n%s", n, out)
	}
}

func TestFlowsRequestFiltersEachNamespace(t *testing.T) {
	req, err := pbParse(flowsRequest([]string{"arc-runners", "workspace"}))
	if err != nil {
		t.Fatal(err)
	}
	if req.uint(3) != 1 {
		t.Error("follow is not set")
	}
	if len(req[6]) != 2 {
		t.Fatalf("%d whitelist filters, want one per namespace", len(req[6]))
	}
	for i, ns := range []string{"arc-runners", "workspace"} {
		ff, _ := pbParse(req[6][i])
		if got := ff.str(2); got != ns+"/" {
			t.Errorf("filter %d source_pod %q", i, got)
		}
		var types []uint64
		for _, et := range ff[6] {
			m, _ := pbParse(et)
			types = append(types, m.uint(1))
		}
		if fmt.Sprint(types) != "[5 129]" {
			t.Errorf("filter %d event types %v", i, types)
		}
	}
}

func TestLoadEgressConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.json")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	good := `{"listen": ":8481", "relay": "hubble-relay.kube-system.svc.cluster.local:80",
	          "policies": [{"namespace": "arc-runners", "name": "arc-runners-egress"}, {"namespace": "workspace", "name": "workspace-egress"}]}`
	if _, err := loadEgressConfig(write(good)); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"unknown field":  `{"listen": ":1", "relay": "r:80", "policies": [{"namespace": "a", "name": "b"}], "cap": 1}`,
		"no relay":       `{"listen": ":1", "policies": [{"namespace": "a", "name": "b"}]}`,
		"no policies":    `{"listen": ":1", "relay": "r:80"}`,
		"no name":        `{"listen": ":1", "relay": "r:80", "policies": [{"namespace": "a"}]}`,
		"same namespace": `{"listen": ":1", "relay": "r:80", "policies": [{"namespace": "a", "name": "b"}, {"namespace": "a", "name": "c"}]}`,
	} {
		if _, err := loadEgressConfig(write(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeKube serves one CiliumNetworkPolicy the way the API server does under a
// Role naming it by resourceNames: only with fieldSelector=metadata.name=<it>.
type fakeKube struct {
	t       *testing.T
	mu      sync.Mutex
	lists   []string
	watches [][]string
	hold    bool
	seenRV  []string
}

func (k *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/apis/cilium.io/v2/namespaces/workspace/ciliumnetworkpolicies" ||
		r.URL.Query().Get("fieldSelector") != "metadata.name=workspace-egress" {
		http.Error(w, `ciliumnetworkpolicies.cilium.io is forbidden`, http.StatusForbidden)
		return
	}
	k.mu.Lock()
	if r.URL.Query().Get("watch") == "1" {
		k.seenRV = append(k.seenRV, r.URL.Query().Get("resourceVersion"))
		if len(k.watches) == 0 {
			k.mu.Unlock()
			http.Error(w, "no watch scripted", http.StatusInternalServerError)
			return
		}
		events := k.watches[0]
		k.watches = k.watches[1:]
		last := len(k.watches) == 0
		k.mu.Unlock()
		for _, ev := range events {
			io.WriteString(w, ev+"\n")
		}
		w.(http.Flusher).Flush()
		if last && k.hold {
			<-r.Context().Done()
		}
		return
	}
	if len(k.lists) == 0 {
		k.mu.Unlock()
		http.Error(w, "no list scripted", http.StatusInternalServerError)
		return
	}
	item := k.lists[0]
	k.lists = k.lists[1:]
	k.mu.Unlock()
	var p cnp
	json.Unmarshal([]byte(item), &p)
	fmt.Fprintf(w, `{"metadata": {"resourceVersion": %q}, "items": [%s]}`, p.Metadata.ResourceVersion, item)
}

func newFakeKube(t *testing.T, k *fakeKube) *kubeClient {
	k.t = t
	srv := httptest.NewTLSServer(k)
	t.Cleanup(srv.Close)
	return &kubeClient{base: srv.URL, client: srv.Client()}
}

func watchEvent(typ, obj string) string {
	return fmt.Sprintf(`{"type": %q, "object": %s}`, typ, obj)
}

func TestWatchPolicyAppliesChangesAndEndsWhenThePolicyGoes(t *testing.T) {
	k := &fakeKube{
		lists: []string{policyJSON("12", "pypi.org")},
		watches: [][]string{
			{watchEvent("MODIFIED", policyJSON("11", "registry.npmjs.org"))},
			{watchEvent("DELETED", policyJSON("13"))},
		},
	}
	kube := newFakeKube(t, k)
	set := &policySet{by: map[string]*egressPolicy{}}
	err := kube.watchPolicy(context.Background(), set, "workspace", "workspace-egress", "10")
	if err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("watch ended with %v, want the policy deleted", err)
	}
	if fmt.Sprint(k.seenRV) != "[10 12]" {
		t.Errorf("watches from resourceVersions %v, want the first given and then the relist's", k.seenRV)
	}
	if p := set.get("workspace"); p == nil || !p.listed("pypi.org") || p.listed("registry.npmjs.org") {
		t.Error("the relist after a watch ended did not replace the policy")
	}
}

func TestWatchPolicyRelistsOnGone(t *testing.T) {
	k := &fakeKube{
		lists:   []string{policyJSON("20", "pypi.org")},
		watches: [][]string{{watchEvent("ERROR", `{"kind": "Status", "code": 410}`)}, {}},
		hold:    true,
	}
	kube := newFakeKube(t, k)
	set := &policySet{by: map[string]*egressPolicy{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- kube.watchPolicy(ctx, set, "workspace", "workspace-egress", "10") }()
	deadline := time.Now().Add(5 * time.Second)
	for set.get("workspace") == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if p := set.get("workspace"); p == nil || !p.listed("pypi.org") {
		t.Error("an expired resourceVersion did not relist")
	}
}

func TestWatchPolicyEndsOnAPolicyItCannotRead(t *testing.T) {
	k := &fakeKube{watches: [][]string{{watchEvent("MODIFIED", `{"metadata": {"name": "workspace-egress"}, "specs": [{}]}`)}}}
	set := &policySet{by: map[string]*egressPolicy{}}
	if err := newFakeKube(t, k).watchPolicy(context.Background(), set, "workspace", "workspace-egress", "1"); err == nil {
		t.Error("a policy changed to one the observer cannot read did not end the watch")
	}
}

func fakeRelay(t *testing.T, got chan<- []byte, responses [][]byte) string {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/observer.Observer/GetFlows" || r.Header.Get("Content-Type") != "application/grpc" || r.ProtoMajor != 2 {
			http.Error(w, "not a gRPC call", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		for _, m := range responses {
			w.Write(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(m))))
			w.Write(m)
		}
		w.Header().Set("Grpc-Status", "14")
		w.Header().Set("Grpc-Message", "relay going away")
	}))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func h2cClient() *http.Client {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &p}}
}

func TestEgressObserveCountsUntilTheRelayStreamEnds(t *testing.T) {
	k := &fakeKube{lists: []string{policyJSON("5")}, watches: [][]string{{}}, hold: true}
	kube := newFakeKube(t, k)
	got := make(chan []byte, 1)
	relay := fakeRelay(t, got, [][]byte{
		dnsRequest("pypi.org.").response(),
		dnsRequest("github.com.").response(),
		policyVerdict("pypi.org", "151.101.0.223", []string{allowAnyEgress}).response(),
		lostEvents(2),
	})
	cfg := &EgressConfig{Listen: ":0", Relay: relay}
	cfg.Policies = append(cfg.Policies, PolicyRef{"workspace", "workspace-egress"})
	c := newUnlistedCounter([]string{"workspace"})

	err := egressObserve(context.Background(), cfg, kube, h2cClient(), c)
	if err == nil || !strings.Contains(err.Error(), `grpc-status "14" relay going away`) {
		t.Fatalf("observer ended with %v, want the relay's status", err)
	}
	req, _ := pbParse((<-got)[5:])
	if len(req[6]) != 1 {
		t.Errorf("request filters %d namespaces", len(req[6]))
	}
	out := metricsText(c)
	for _, want := range []string{
		`{policy_namespace="workspace",kind="dns",destination="pypi.org."} 1`,
		`{policy_namespace="workspace",kind="connection",destination="pypi.org"} 1`,
		"via_maris_egress_lost_events_total 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "github.com") {
		t.Error("a listed name was counted")
	}
}

func TestEgressObserveEndsOnARelayMessageItCannotRead(t *testing.T) {
	k := &fakeKube{lists: []string{policyJSON("5")}, watches: [][]string{{}}, hold: true}
	got := make(chan []byte, 1)
	relay := fakeRelay(t, got, [][]byte{dnsRequest("pypi.org.").response(), {0xff}})
	cfg := &EgressConfig{Listen: ":0", Relay: relay, Policies: []PolicyRef{{"workspace", "workspace-egress"}}}
	err := egressObserve(context.Background(), cfg, newFakeKube(t, k), h2cClient(), newUnlistedCounter([]string{"workspace"}))
	if err == nil || !strings.Contains(err.Error(), "relay message") {
		t.Fatalf("observer ended with %v, want the unreadable message", err)
	}
}

func TestEgressObserveEndsWhenAPolicyCannotBeRead(t *testing.T) {
	kube := newFakeKube(t, &fakeKube{})
	cfg := &EgressConfig{Listen: ":0", Relay: "127.0.0.1:1"}
	cfg.Policies = append(cfg.Policies, PolicyRef{"arc-runners", "arc-runners-egress"})
	err := egressObserve(context.Background(), cfg, kube, h2cClient(), newUnlistedCounter([]string{"arc-runners"}))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("observer ended with %v, want the API server's refusal", err)
	}
}
