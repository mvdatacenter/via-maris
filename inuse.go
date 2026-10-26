package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type inUseFile struct {
	Generated      time.Time                                  `json:"generated"`
	Ecosystems     map[string]map[string][]string             `json:"ecosystems"`
	RecordsThrough time.Time                                  `json:"recordsThrough,omitzero"`
	Served         map[string]map[string]map[string]time.Time `json:"served,omitempty"`
}

type inUseSet struct {
	store  *objectStore
	object string
	mu     sync.RWMutex
	data   map[string]map[string][]string
	// generated is when the run that wrote the object started, so an object
	// that stops being rewritten ages even while it still loads.
	generated time.Time
	count     int
}

func (s *inUseSet) load(ctx context.Context) error {
	body, err := s.store.get(ctx, s.object)
	if err != nil {
		return err
	}
	defer body.Close()
	var f inUseFile
	if err := json.NewDecoder(body).Decode(&f); err != nil {
		return fmt.Errorf("%s: %w", s.object, err)
	}
	if f.Generated.IsZero() {
		return fmt.Errorf("%s: no generated time", s.object)
	}
	data := map[string]map[string][]string{}
	n := 0
	for eco, pkgs := range f.Ecosystems {
		data[eco] = map[string][]string{}
		for name, vs := range pkgs {
			k := packageKey(eco, name)
			data[eco][k] = append(data[eco][k], vs...)
			n += len(vs)
		}
	}
	s.mu.Lock()
	s.data, s.generated, s.count = data, f.Generated, n
	s.mu.Unlock()
	return nil
}

func (s *inUseSet) versions(eco, name string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[eco][packageKey(eco, name)]
}

func (s *inUseSet) age() (time.Duration, int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.generated.IsZero() {
		return 0, 0, false
	}
	return time.Since(s.generated), s.count, true
}
