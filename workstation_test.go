package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (env *testEnv) report(body string) (int, string) {
	env.t.Helper()
	resp, err := http.Post(env.srv.URL+"/workstation-route", "application/json", strings.NewReader(body))
	if err != nil {
		env.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The report path serves alongside any front end, so one npm upstream that is
// never asked stands in for the configuration.
func newWorkstationEnv(t *testing.T) *testEnv {
	return newTestEnv(t, Upstream{Name: "npm", Ecosystem: "npm", URL: "http://127.0.0.1:1", Hold: Duration{7 * day}, Advisories: "malicious"})
}

func TestWorkstationReportSetsItsSeries(t *testing.T) {
	env := newWorkstationEnv(t)
	at := time.Unix(1795000000, 0)
	env.g.stations.now = func() time.Time { return at }
	if code, body := env.report(`{"workstation":"dev-1","settings":{"pip-proxy":2,"npm-cafile":0}}`); code != http.StatusNoContent {
		t.Fatalf("report answered %d %q, want 204", code, body)
	}
	_, metrics := env.get("/metrics")
	wantContains(t, metrics,
		`via_maris_workstation_route_report_timestamp_seconds{workstation="dev-1"} 1795000000`+"\n",
		`via_maris_workstation_route_differing_reports{workstation="dev-1",setting="npm-cafile"} 0`+"\n",
		`via_maris_workstation_route_differing_reports{workstation="dev-1",setting="pip-proxy"} 2`+"\n",
	)

	// The next report replaces the last, so a setting it leaves out loses its series.
	env.g.stations.now = func() time.Time { return at.Add(time.Hour) }
	env.report(`{"workstation":"dev-1","settings":{"npm-cafile":1}}`)
	_, metrics = env.get("/metrics")
	wantContains(t, metrics,
		`via_maris_workstation_route_report_timestamp_seconds{workstation="dev-1"} 1795003600`,
		`via_maris_workstation_route_differing_reports{workstation="dev-1",setting="npm-cafile"} 1`,
	)
	if strings.Contains(metrics, `setting="pip-proxy"`) {
		t.Errorf("a setting the last report left out kept its series: %q", metrics)
	}
}

func TestWorkstationReportRefusesWhatItCannotCount(t *testing.T) {
	env := newWorkstationEnv(t)
	for _, c := range []struct{ body, want string }{
		{`{"workstation":"dev 1","settings":{}}`, `workstation "dev 1" is not 1 to 63 letters`},
		{`{"workstation":"","settings":{}}`, `workstation "" is not`},
		{`{"workstation":"dev-1","settings":{"registry":1}}`, `setting "registry" is not one this gateway counts`},
		{`{"workstation":"dev-1","settings":{"pip-proxy":-1}}`, `setting "pip-proxy" has -1 differing reports`},
		{`{"workstation":"dev-1","settings":{"pip-proxy":1048577}}`, `setting "pip-proxy" has 1048577 differing reports, outside 0 to 1048576`},
		{`{"workstation":"dev-1","settings":{}}` + strings.Repeat(" ", maxReportBytes), `body is over 4096 bytes`},
		{`{"workstation":"dev-1","settings":{}} {}`, `body holds more than one JSON object`},
		{`{"workstation":"dev-1","settings":{},"extra":1}`, `unknown field "extra"`},
		{`not json`, `invalid character`},
	} {
		code, body := env.report(c.body)
		if code != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("report %s answered %d %q, want 400 naming %q", c.body, code, body, c.want)
		}
	}
	if code, _ := env.get("/workstation-route"); code != http.StatusMethodNotAllowed {
		t.Errorf("GET answered %d, want 405", code)
	}
	if _, metrics := env.get("/metrics"); strings.Contains(metrics, "via_maris_workstation_route") {
		t.Errorf("a refused report set a series: %q", metrics)
	}
}

func TestWorkstationReportsPastTheBoundDropTheOldest(t *testing.T) {
	env := newWorkstationEnv(t)
	at := time.Unix(1795000000, 0)
	for i := 0; i < maxWorkstations; i++ {
		env.g.stations.now = func() time.Time { return at.Add(time.Duration(i) * time.Minute) }
		if code, body := env.report(fmt.Sprintf(`{"workstation":"dev-%d","settings":{}}`, i)); code != http.StatusNoContent {
			t.Fatalf("report %d answered %d %q", i, code, body)
		}
	}
	env.g.stations.now = func() time.Time { return at.Add(24 * time.Hour) }
	if code, body := env.report(`{"workstation":"dev-0","settings":{"pip-cert":1}}`); code != http.StatusNoContent {
		t.Fatalf("a workstation already held answered %d %q at the bound", code, body)
	}
	if code, body := env.report(`{"workstation":"one-more","settings":{}}`); code != http.StatusNoContent {
		t.Fatalf("a workstation past the bound answered %d %q, want 204", code, body)
	}
	_, metrics := env.get("/metrics")
	if strings.Contains(metrics, `workstation="dev-1"}`) {
		t.Errorf("the oldest report, dev-1's, was kept past the bound")
	}
	wantContains(t, metrics, `workstation="one-more"}`, `workstation="dev-0"}`, `workstation="dev-2"}`)
	if n := strings.Count(metrics, "via_maris_workstation_route_report_timestamp_seconds{"); n != maxWorkstations {
		t.Errorf("metrics hold %d workstations, want %d", n, maxWorkstations)
	}
}
