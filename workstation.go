package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

// docs/configuration.md, "Workstation route reports", holds why these reports exist,
// their body and the series they set.

var workstationSettings = map[string]bool{
	"uv-wrapper":      true,
	"pip-proxy":       true,
	"pip-cert":        true,
	"npm-https-proxy": true,
	"npm-cafile":      true,
	"gradle-block":    true,
}

// maxWorkstations bounds the series a stream of invented names can add.
const maxWorkstations = 256

// maxDiffering bounds a run so the gauge stays an integer Prometheus holds
// exactly; a run that long has fired its alert for over a year.
const maxDiffering = 1 << 20

const maxReportBytes = 4096

var workstationName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

type workstationReport struct {
	Workstation string         `json:"workstation"`
	Settings    map[string]int `json:"settings"`
}

type workstationRoute struct {
	at       time.Time
	settings map[string]int
}

type workstationRoutes struct {
	mu   sync.Mutex
	now  func() time.Time
	last map[string]workstationRoute
}

func newWorkstationRoutes() *workstationRoutes {
	return &workstationRoutes{now: time.Now, last: map[string]workstationRoute{}}
}

func (s *workstationRoutes) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "via-maris: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rep, err := readWorkstationReport(r.Body)
	if err == nil {
		err = rep.valid()
	}
	if err != nil {
		http.Error(w, "via-maris: workstation report: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if _, known := s.last[rep.Workstation]; !known && len(s.last) >= maxWorkstations {
		oldest := s.oldest()
		log.Printf("workstation report: dropped %s's report from %s to hold %s's, past the bound of %d workstations", oldest, s.last[oldest].at.UTC().Format(time.RFC3339), rep.Workstation, maxWorkstations)
		delete(s.last, oldest)
	}
	s.last[rep.Workstation] = workstationRoute{at: s.now(), settings: rep.Settings}
	s.mu.Unlock()
	for _, name := range sortedKeys(rep.Settings) {
		if n := rep.Settings[name]; n > 0 {
			log.Printf("workstation report: %s: %s differed in the last %d of its reports", rep.Workstation, name, n)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *workstationRoutes) oldest() string {
	var name string
	for n, r := range s.last {
		if name == "" || r.at.Before(s.last[name].at) || (r.at.Equal(s.last[name].at) && n < name) {
			name = n
		}
	}
	return name
}

func readWorkstationReport(body io.Reader) (*workstationReport, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxReportBytes {
		return nil, fmt.Errorf("body is over %d bytes", maxReportBytes)
	}
	var rep workstationReport
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("body holds more than one JSON object")
	}
	return &rep, nil
}

func (rep *workstationReport) valid() error {
	if !workstationName.MatchString(rep.Workstation) {
		return fmt.Errorf("workstation %q is not 1 to 63 letters, digits, dots, underscores or hyphens", rep.Workstation)
	}
	for name, n := range rep.Settings {
		if !workstationSettings[name] {
			return fmt.Errorf("setting %q is not one this gateway counts", name)
		}
		if n < 0 || n > maxDiffering {
			return fmt.Errorf("setting %q has %d differing reports, outside 0 to %d", name, n, maxDiffering)
		}
	}
	return nil
}

func (s *workstationRoutes) metrics(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.last))
	for name := range s.last {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		last := s.last[name]
		fmt.Fprintf(w, "via_maris_workstation_route_report_timestamp_seconds{workstation=%q} %d\n", name, last.at.Unix())
		for _, setting := range sortedKeys(last.settings) {
			fmt.Fprintf(w, "via_maris_workstation_route_differing_reports{workstation=%q,setting=%q} %d\n", name, setting, last.settings[setting])
		}
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
