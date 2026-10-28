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
	t.Setenv("RECORDS_ENDPOINT", "https://account.records.example")
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
	if got := newObjectStore(cfg.Records.Store, nil).objectURL("k"); got != "https://account.records.example/via-maris-records/k" {
		t.Errorf("records object URL %s, want the endpoint RECORDS_ENDPOINT holds", got)
	}
	if cfg.ByName == nil || cfg.ByName.Upstream != "pypi" {
		t.Errorf("byName %+v", cfg.ByName)
	}
	if n := cfg.ByName.NPM; n == nil || n.Upstream != "npm" || strings.Join(n.Hosts, " ") != "registry.npmjs.org registry.yarnpkg.com" {
		t.Errorf("byName.npm %+v", cfg.ByName.NPM)
	}
}

func byNameNPM(c map[string]any) map[string]any {
	return c["byName"].(map[string]any)["npm"].(map[string]any)
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
			c["records"].(map[string]any)["store"].(map[string]any)["endpoint"] = "https://records-store.example.com"
		}, "records.store names both endpoint and endpointEnv"},
		{"unset endpoint", func(c map[string]any) {
			c["records"].(map[string]any)["store"].(map[string]any)["endpointEnv"] = "VIA_MARIS_TEST_UNSET"
		}, "records.store: endpointEnv names VIA_MARIS_TEST_UNSET, which must be set to an http(s) endpoint"},
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
		{"by name on npm", func(c map[string]any) { c["byName"].(map[string]any)["upstream"] = "npm" }, "byName.upstream npm is not a PyPI upstream"},
		{"by name on no upstream", func(c map[string]any) { c["byName"].(map[string]any)["upstream"] = "pip" }, `byName.upstream "pip" names no upstream`},
		{"by name on the main listener", func(c map[string]any) { c["byName"].(map[string]any)["listen"] = ":8480" }, "byName.listen is required and differs from listen"},
		{"by name without a CA", func(c map[string]any) { delete(c["byName"].(map[string]any), "ca") }, "byName needs cert, key and ca files"},
		{"by name with files on the index host", func(c map[string]any) { upstreamAt(c, 1)["files"] = "https://pypi.org/files" }, "serves its index and files from one host"},
		{"npm by name on pypi", func(c map[string]any) { byNameNPM(c)["upstream"] = "pypi" }, "byName.npm.upstream pypi is not an npm upstream"},
		{"npm by name on no upstream", func(c map[string]any) { byNameNPM(c)["upstream"] = "yarn" }, `byName.npm.upstream "yarn" names no upstream`},
		{"npm by name without a key", func(c map[string]any) { delete(byNameNPM(c), "key") }, "byName.npm needs cert, key and ca files"},
		{"npm by name without the registry's host", func(c map[string]any) { byNameNPM(c)["hosts"] = []any{"registry.yarnpkg.com"} }, "byName.npm.hosts must include registry.npmjs.org"},
		{"npm by name on a PyPI name", func(c map[string]any) { byNameNPM(c)["hosts"] = []any{"registry.npmjs.org", "pypi.org"} }, "byName.npm.hosts entry pypi.org is already a PyPI name"},
		{"npm by name with a port", func(c map[string]any) { byNameNPM(c)["hosts"] = []any{"registry.npmjs.org:443"} }, `byName.npm.hosts entry "registry.npmjs.org:443" is not a bare host name`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadConfig(writeVariant(t, c.edit))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want it to contain %q", err, c.want)
			}
		})
	}
}
