package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setExampleKeys(t *testing.T) {
	for _, env := range []string{"IN_USE_ACCESS_KEY_ID", "IN_USE_SECRET_ACCESS_KEY", "RECORDS_ACCESS_KEY_ID", "RECORDS_SECRET_ACCESS_KEY"} {
		t.Setenv(env, "x")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	setExampleKeys(t)
	cfg, err := loadConfig("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Upstreams) != 5 || cfg.Upstreams[0].Exceptions[0].Expires.Format("2006-01-02") != "2026-12-01" {
		t.Errorf("loaded %+v", cfg.Upstreams)
	}
}

func TestEndpointFromEnvironment(t *testing.T) {
	setExampleKeys(t)
	t.Setenv("RECORDS_ENDPOINT", "https://account.records.example")
	cfg, err := loadConfig(writeVariant(t, func(c map[string]any) {
		st := c["records"].(map[string]any)["store"].(map[string]any)
		delete(st, "endpoint")
		st["endpointEnv"] = "RECORDS_ENDPOINT"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := newObjectStore(cfg.Records.Store, nil).objectURL("k"); got != "https://account.records.example/via-maris-records/k" {
		t.Errorf("object URL %s", got)
	}
}

func writeVariant(t *testing.T, edit func(c map[string]any)) string {
	t.Helper()
	b, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	edit(c)
	out, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func upstreamAt(c map[string]any, i int) map[string]any {
	return c["upstreams"].([]any)[i].(map[string]any)
}

func TestConfigRefusals(t *testing.T) {
	setExampleKeys(t)
	for _, c := range []struct {
		name string
		edit func(c map[string]any)
		want string
	}{
		{"unknown field", func(c map[string]any) { c["upstream"] = 1 }, `unknown field "upstream"`},
		{"advisory bound below refresh", func(c map[string]any) { c["advisories"].(map[string]any)["maxAge"] = "10m" }, "advisories.maxAge must exceed"},
		{"source with trailing slash", func(c map[string]any) { c["advisories"].(map[string]any)["source"] = "https://osv.example/" }, "advisories.source must be"},
		{"unset key", func(c map[string]any) {
			c["records"].(map[string]any)["store"].(map[string]any)["secretAccessKeyEnv"] = "VIA_MARIS_TEST_UNSET"
		}, "records.store: accessKeyIdEnv and secretAccessKeyEnv must name environment variables that are set"},
		{"both endpoints", func(c map[string]any) {
			c["records"].(map[string]any)["store"].(map[string]any)["endpointEnv"] = "RECORDS_ENDPOINT"
		}, "records.store names both endpoint and endpointEnv"},
		{"unset endpoint", func(c map[string]any) {
			st := c["records"].(map[string]any)["store"].(map[string]any)
			delete(st, "endpoint")
			st["endpointEnv"] = "VIA_MARIS_TEST_UNSET"
		}, "records.store needs an http(s) endpoint"},
		{"records bound below interval", func(c map[string]any) { c["records"].(map[string]any)["maxUnshipped"] = "5s" }, "records.maxUnshipped must exceed"},
		{"repeated name", func(c map[string]any) { upstreamAt(c, 1)["name"] = "npm" }, `upstream name "npm"`},
		{"reserved name", func(c map[string]any) { upstreamAt(c, 0)["name"] = "metrics" }, `upstream name "metrics"`},
		{"unknown ecosystem", func(c map[string]any) { upstreamAt(c, 0)["ecosystem"] = "cargo" }, `ecosystem "cargo"`},
		{"no hold", func(c map[string]any) { delete(upstreamAt(c, 0), "hold") }, "upstream npm has no hold"},
		{"bad policy", func(c map[string]any) { upstreamAt(c, 0)["advisories"] = "none" }, "advisories must be malicious or all"},
		{"exception without expiry", func(c map[string]any) {
			delete(upstreamAt(c, 0)["exceptions"].([]any)[0].(map[string]any), "expires")
		}, "an exception needs package, version, reason, reviewed and expires"},
		{"pypi without files", func(c map[string]any) { delete(upstreamAt(c, 1), "files") }, "upstream pypi: files must be"},
		{"go without sumdb", func(c map[string]any) { delete(upstreamAt(c, 2), "sumdb") }, "upstream go: sumdb must be"},
		{"go index bound below poll", func(c map[string]any) { upstreamAt(c, 2)["indexMaxAge"] = "30s" }, "indexMaxAge must exceed"},
		{"apt with advisories", func(c map[string]any) { upstreamAt(c, 3)["advisories"] = "malicious" }, "held by its snapshot date alone"},
		{"files with a hold", func(c map[string]any) { upstreamAt(c, 4)["hold"] = "1h" }, "takes pinned files alone"},
		{"file climbing out", func(c map[string]any) {
			upstreamAt(c, 4)["pinned"].([]any)[0].(map[string]any)["name"] = "../x"
		}, "climbs out"},
		{"file without digest", func(c map[string]any) {
			upstreamAt(c, 4)["pinned"].([]any)[0].(map[string]any)["sha256"] = "ABC"
		}, "needs a lower-case hex sha256"},
		{"no upstreams", func(c map[string]any) { c["upstreams"] = []any{} }, "upstreams is empty"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadConfig(writeVariant(t, c.edit))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want it to contain %q", err, c.want)
			}
		})
	}
}
