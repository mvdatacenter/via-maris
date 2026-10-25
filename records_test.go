package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRecordsAreShippedAndAFailedUploadKeepsThem(t *testing.T) {
	reg := newFakeNPM(t)
	reg.packages["left-pad"] = map[string]time.Duration{"1.3.0": 1000 * day}
	env := newTestEnv(t, npmUpstream(reg.srv.URL))
	env.loadAdvisories()

	env.store.setFail(true)
	env.get("/npm/left-pad/-/left-pad-1.3.0.tgz")
	if err := env.g.records.ship(context.Background()); err == nil {
		t.Fatal("ship succeeded against a failing store")
	}
	if env.g.records.unshipped() == 0 {
		t.Fatal("a failed upload dropped its records")
	}

	env.store.setFail(false)
	if err := env.g.records.ship(context.Background()); err != nil {
		t.Fatal(err)
	}
	if age := env.g.records.unshipped(); age != 0 {
		t.Errorf("unshipped %s after a successful upload", age)
	}
	keys := env.store.keys("/bucket/records/")
	if len(keys) != 1 || !strings.HasSuffix(keys[0], ".ndjson") {
		t.Fatalf("uploaded %v", keys)
	}
	env.store.mu.Lock()
	body := string(env.store.objects[keys[0]])
	env.store.mu.Unlock()
	wantContains(t, body, `"package":"left-pad"`, `"version":"1.3.0"`, `"served":true`)
}

func TestRequestsAreRefusedWhileRecordsCannotReachStorage(t *testing.T) {
	reg := newFakeNPM(t)
	reg.packages["left-pad"] = map[string]time.Duration{"1.3.0": 1000 * day}
	env := newTestEnv(t, npmUpstream(reg.srv.URL))
	env.loadAdvisories()

	env.g.records.mu.Lock()
	env.g.records.pending = append(env.g.records.pending, pendingRecord{time.Now().Add(-2 * time.Minute), []byte("{}\n")})
	env.g.records.mu.Unlock()

	status, body := env.get("/npm/left-pad/-/left-pad-1.3.0.tgz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", status, body)
	}
	wantContains(t, body, "decision records have not reached storage for 2m0s, past the 1m0s bound")
	status, body = env.get("/healthz")
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "not ready: records") {
		t.Errorf("healthz: %d %q", status, body)
	}

	if err := env.g.records.ship(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, _ := env.get("/npm/left-pad/-/left-pad-1.3.0.tgz"); status != http.StatusOK {
		t.Errorf("after the upload: %d", status)
	}
	status, body = env.get("/healthz")
	if status != http.StatusOK || body != "ready (via-maris dev)\n" {
		t.Errorf("healthz: %d %q", status, body)
	}
	_, body = env.get("/metrics")
	wantContains(t, body, `via_maris_build_info{version="dev"} 1`, `via_maris_decisions_total{served="true"} 1`, `via_maris_decisions_total{served="false"} 1`, "via_maris_records_unshipped_seconds 0")
}
