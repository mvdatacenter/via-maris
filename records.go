package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type record struct {
	Time      string `json:"time"`
	Client    string `json:"client"`
	Upstream  string `json:"upstream"`
	Ecosystem string `json:"ecosystem"`
	Kind      string `json:"kind"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Served    bool   `json:"served"`
	Reason    string `json:"reason"`
}

type pendingRecord struct {
	at   time.Time
	line []byte
}

// recorder writes each decision to its log and uploads them in batches, so
// the record survives the loss of the gateway's host. Records not yet
// uploaded live only in memory.
type recorder struct {
	log     io.Writer
	store   *objectStore
	prefix  string
	host    string
	mu      sync.Mutex
	pending []pendingRecord
	// shipMu keeps one upload in flight, so two never take the same records.
	shipMu  sync.Mutex
	served  atomic.Int64
	refused atomic.Int64
}

func (r *recorder) write(rec record) {
	if rec.Served {
		r.served.Add(1)
	} else {
		r.refused.Add(1)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		panic(err) // a record holds strings and a bool alone
	}
	line = append(line, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Write(line)
	r.pending = append(r.pending, pendingRecord{time.Now(), line})
}

func (r *recorder) unshipped() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return 0
	}
	return time.Since(r.pending[0].at)
}

func (r *recorder) ship(ctx context.Context) error {
	r.shipMu.Lock()
	defer r.shipMu.Unlock()
	r.mu.Lock()
	n := len(r.pending)
	var batch bytes.Buffer
	for _, p := range r.pending {
		batch.Write(p.line)
	}
	r.mu.Unlock()
	if n == 0 {
		return nil
	}
	now := time.Now().UTC()
	key := r.prefix + now.Format("2006-01-02") + "/" + now.Format("150405.000000000") + "-" + r.host + ".ndjson"
	if err := r.store.put(ctx, key, "application/x-ndjson", batch.Bytes()); err != nil {
		return err
	}
	r.mu.Lock()
	r.pending = r.pending[n:]
	r.mu.Unlock()
	return nil
}

// run ships on every interval until ctx ends, then once more with a short
// deadline of its own, so a stopping replica uploads what it decided.
func (r *recorder) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := r.ship(final); err != nil {
				log.Printf("records: final upload: %v", err)
			}
			return
		case <-t.C:
			attempt, cancel := context.WithTimeout(ctx, interval)
			if err := r.ship(attempt); err != nil {
				log.Printf("records: %v", err)
			}
			cancel()
		}
	}
}
