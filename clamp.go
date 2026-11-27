package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const clampMarkerPrefix = "<!-- via-maris-clamp: head="

type DependabotClampConfig struct {
	Gateway  string `json:"gateway"`
	Upstream string `json:"upstream"`
	GitHub   struct {
		API               string `json:"api"`
		Owner             string `json:"owner"`
		AppIDEnv          string `json:"appIdEnv"`
		InstallationIDEnv string `json:"installationIdEnv"`
		PrivateKeyEnv     string `json:"privateKeyEnv"`
	} `json:"github"`
	MaxWritesPerPass int `json:"maxWritesPerPass"`
}

func loadDependabotClampConfig(filePath string) (*DependabotClampConfig, error) {
	var c DependabotClampConfig
	if err := decodeStrict(filePath, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	return &c, nil
}

func (c *DependabotClampConfig) validate() error {
	if !httpURL(c.Gateway) {
		return errors.New("gateway must be an http(s) URL without a trailing slash")
	}
	if !upstreamName.MatchString(c.Upstream) || c.Upstream == "healthz" || c.Upstream == "metrics" || c.Upstream == "verdicts" {
		return fmt.Errorf("upstream %q must be a lower-case upstream name", c.Upstream)
	}
	gh := c.GitHub
	if !httpURL(gh.API) || gh.Owner == "" {
		return errors.New("github needs an http(s) api URL without a trailing slash, and an owner")
	}
	for _, env := range []string{gh.AppIDEnv, gh.InstallationIDEnv, gh.PrivateKeyEnv} {
		if env == "" || os.Getenv(env) == "" {
			return errors.New("github: appIdEnv, installationIdEnv and privateKeyEnv must name environment variables that are set")
		}
	}
	if c.MaxWritesPerPass <= 0 {
		return errors.New("maxWritesPerPass must be positive")
	}
	return nil
}

type clampRun struct {
	cfg      *DependabotClampConfig
	gh       *githubApp
	verdicts *verdictClient
}

func newClampRun(cfg *DependabotClampConfig, client *http.Client) (*clampRun, error) {
	key, err := parseAppKey(os.Getenv(cfg.GitHub.PrivateKeyEnv))
	if err != nil {
		return nil, err
	}
	gh := &githubApp{
		api:            cfg.GitHub.API,
		appID:          os.Getenv(cfg.GitHub.AppIDEnv),
		installationID: os.Getenv(cfg.GitHub.InstallationIDEnv),
		key:            key,
		client:         client,
	}
	return &clampRun{
		cfg: cfg,
		gh:  gh,
		verdicts: &verdictClient{
			gateway:  cfg.Gateway,
			upstream: cfg.Upstream,
			client:   client,
			cache:    map[string]*npmVerdictsResponse{},
		},
	}, nil
}

func clampDependabotMain(cfgPath string, client *http.Client) error {
	cfg, err := loadDependabotClampConfig(cfgPath)
	if err != nil {
		return err
	}
	run, err := newClampRun(cfg, client)
	if err != nil {
		return err
	}
	return run.run(context.Background())
}

type verdictClient struct {
	gateway  string
	upstream string
	client   *http.Client
	cache    map[string]*npmVerdictsResponse
}

func (vc *verdictClient) get(ctx context.Context, pkg string) (*npmVerdictsResponse, error) {
	if cached, ok := vc.cache[pkg]; ok {
		return cached, nil
	}
	u := vc.gateway + "/verdicts/" + vc.upstream + "/" + url.PathEscape(pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "via-maris/"+version)
	resp, err := vc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verdicts %s: %w", pkg, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("verdicts %s: %w", pkg, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verdicts %s: %s %s", pkg, resp.Status, strings.TrimSpace(string(body[:min(len(body), 512)])))
	}
	var out npmVerdictsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("verdicts %s: %w", pkg, err)
	}
	vc.cache[pkg] = &out
	return &out, nil
}

type clampStats struct {
	scanned   int
	committed int
	commented int
	skipped   int
}

func (r *clampRun) run(ctx context.Context) error {
	if err := r.gh.mintWithPermissions(ctx, map[string]string{
		"contents":      "write",
		"pull_requests": "write",
	}); err != nil {
		return err
	}
	repos, err := r.gh.repositories(ctx, r.cfg.GitHub.Owner)
	if err != nil {
		return err
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].FullName < repos[j].FullName })

	var stats clampStats
	writes := 0
	for _, repo := range repos {
		if writes >= r.cfg.MaxWritesPerPass {
			log.Printf("clamp-dependabot: reached maxWritesPerPass (%d), stopping pass", r.cfg.MaxWritesPerPass)
			break
		}
		prs, err := r.gh.openPullRequests(ctx, repo.FullName)
		if err != nil {
			return err
		}
		sort.Slice(prs, func(i, j int) bool { return prs[i].Number < prs[j].Number })
		for _, pr := range prs {
			if writes >= r.cfg.MaxWritesPerPass {
				log.Printf("clamp-dependabot: reached maxWritesPerPass (%d), stopping pass", r.cfg.MaxWritesPerPass)
				break
			}
			if !eligibleDependabotPR(pr) {
				continue
			}
			files, err := r.gh.pullRequestFiles(ctx, repo.FullName, pr.Number)
			if err != nil {
				return err
			}
			lockfiles := eligibleLockfiles(files)
			if len(lockfiles) == 0 {
				continue
			}
			stats.scanned++
			didWrite, action, err := r.processPR(ctx, repo.FullName, pr, lockfiles)
			if err != nil {
				return err
			}
			if didWrite {
				writes++
			}
			switch action {
			case "committed":
				stats.committed++
			case "commented":
				stats.commented++
			default:
				stats.skipped++
			}
		}
	}
	log.Printf("clamp-dependabot: scanned %d pull requests, committed %d, commented %d, skipped %d",
		stats.scanned, stats.committed, stats.commented, stats.skipped)
	return nil
}

func eligibleDependabotPR(pr pullRequest) bool {
	if pr.User.Login != "dependabot[bot]" {
		return false
	}
	if pr.Head.Repo == nil || pr.Base.Repo == nil {
		return false
	}
	return strings.EqualFold(pr.Head.Repo.FullName, pr.Base.Repo.FullName)
}

func eligibleLockfiles(files []pullFile) []pullFile {
	if len(files) == 0 {
		return nil
	}
	var locks []pullFile
	for _, f := range files {
		base := path.Base(f.Filename)
		switch base {
		case "package.json":
		case "yarn.lock", "package-lock.json":
			if f.Status != "removed" {
				locks = append(locks, f)
			}
		default:
			return nil
		}
	}
	sort.Slice(locks, func(i, j int) bool { return locks[i].Filename < locks[j].Filename })
	return locks
}

func (r *clampRun) processPR(ctx context.Context, fullName string, pr pullRequest, lockfiles []pullFile) (bool, string, error) {
	updates := map[string]string{}
	var allClamped, allBlocking []string

	for _, lf := range lockfiles {
		dir := path.Dir(lf.Filename)
		pkgPath := "package.json"
		if dir != "." {
			pkgPath = dir + "/package.json"
		}
		pkgBytes, err := r.gh.fileContent(ctx, fullName, pkgPath, pr.Head.SHA)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("clamp-dependabot: %s#%d: missing %s at %s, skipping", fullName, pr.Number, pkgPath, pr.Head.SHA)
				return false, "skipped", nil
			}
			return false, "", err
		}
		headLock, err := r.gh.fileContent(ctx, fullName, lf.Filename, pr.Head.SHA)
		if err != nil {
			return false, "", err
		}
		baseLock, err := r.gh.fileContent(ctx, fullName, lf.Filename, pr.Base.SHA)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				baseLock = nil
			} else {
				return false, "", err
			}
		}

		var (
			newLock  string
			changed  bool
			clamped  []string
			blocking []string
		)
		switch path.Base(lf.Filename) {
		case "yarn.lock":
			newLock, changed, clamped, blocking, err = clampYarnLock(ctx, r.verdicts, string(pkgBytes), string(baseLock), string(headLock))
		case "package-lock.json":
			newLock, changed, clamped, blocking, err = clampPackageLock(ctx, r.verdicts, string(pkgBytes), string(baseLock), string(headLock))
		}
		if err != nil {
			if errors.Is(err, errUnsupportedLockfile) {
				log.Printf("clamp-dependabot: %s#%d: %s: %v, skipping", fullName, pr.Number, lf.Filename, err)
				return false, "skipped", nil
			}
			return false, "", fmt.Errorf("%s#%d (%s): %w", fullName, pr.Number, lf.Filename, err)
		}
		for _, b := range blocking {
			allBlocking = append(allBlocking, fmt.Sprintf("%s: %s", lf.Filename, b))
		}
		for _, c := range clamped {
			allClamped = append(allClamped, fmt.Sprintf("%s: %s", lf.Filename, c))
		}
		if changed {
			updates[lf.Filename] = newLock
		}
	}

	if len(allBlocking) > 0 {
		wrote, err := r.upsertBlockingComment(ctx, fullName, pr, allBlocking)
		if err != nil {
			return false, "", err
		}
		if wrote {
			log.Printf("clamp-dependabot: %s#%d: posted unclampable notice for head %s (%d blocking)", fullName, pr.Number, pr.Head.SHA, len(allBlocking))
			return true, "commented", nil
		}
		return false, "skipped", nil
	}

	if len(updates) == 0 {
		return false, "skipped", nil
	}

	msg := formatClampCommitMessage(allClamped)
	sha, err := r.gh.commitFiles(ctx, fullName, pr.Head.Ref, pr.Head.SHA, msg, updates)
	if errors.Is(err, errRefMoved) {
		log.Printf("clamp-dependabot: %s#%d: head ref %s moved before update, will re-read on next pass", fullName, pr.Number, pr.Head.Ref)
		return false, "skipped", nil
	}
	if err != nil {
		return false, "", err
	}
	log.Printf("clamp-dependabot: %s#%d: committed %s clamping %d transitive entries", fullName, pr.Number, sha, len(allClamped))
	return true, "committed", nil
}

func formatClampCommitMessage(clamped []string) string {
	var b strings.Builder
	b.WriteString("chore(deps): clamp held transitive npm versions to via-maris served releases\n\n")
	b.WriteString("Clamped transitive lockfile entries refused by via-maris:\n")
	for _, line := range clamped {
		b.WriteString("- ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func (r *clampRun) upsertBlockingComment(ctx context.Context, fullName string, pr pullRequest, blocking []string) (bool, error) {
	comments, err := r.gh.issueComments(ctx, fullName, pr.Number)
	if err != nil {
		return false, err
	}
	exactMarker := fmt.Sprintf("%s%s -->", clampMarkerPrefix, pr.Head.SHA)
	var existingID int64
	for _, c := range comments {
		if strings.Contains(c.Body, exactMarker) {
			return false, nil
		}
		if existingID == 0 && strings.Contains(c.Body, clampMarkerPrefix) {
			existingID = c.ID
		}
	}
	body := formatBlockingComment(pr.Head.SHA, blocking)
	if existingID != 0 {
		if err := r.gh.updateIssueComment(ctx, fullName, existingID, body); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := r.gh.createIssueComment(ctx, fullName, pr.Number, body); err != nil {
		return false, err
	}
	return true, nil
}

func formatBlockingComment(headSHA string, blocking []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s -->\n", clampMarkerPrefix, headSHA)
	b.WriteString("`via-maris clamp-dependabot` could not clamp this pull request's lockfile to versions `via-maris` serves:\n\n")
	for _, line := range blocking {
		b.WriteString("- ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

var errUnsupportedLockfile = errors.New("unsupported lockfile format")

type partialSemver struct {
	nums [3]int
	has  [3]bool
	pre  []string
}

func parsePartialSemver(s string) (partialSemver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "vV=")
	if s == "" || s == "*" || s == "x" || s == "X" {
		return partialSemver{}, true
	}
	s, _, _ = strings.Cut(s, "+")
	mainPart, prePart, hasPre := strings.Cut(s, "-")
	parts := strings.Split(mainPart, ".")
	if len(parts) > 3 {
		return partialSemver{}, false
	}
	var out partialSemver
	for i, p := range parts {
		if p == "" || p == "*" || p == "x" || p == "X" {
			break
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return partialSemver{}, false
		}
		out.nums[i] = n
		out.has[i] = true
	}
	if hasPre && prePart != "" {
		out.pre = strings.Split(prePart, ".")
	}
	return out, true
}

type semverBound struct {
	op  string
	ver semver
}

func expandComparator(comp string) ([]semverBound, bool) {
	comp = strings.TrimSpace(comp)
	if comp == "" || comp == "*" || comp == "x" || comp == "X" {
		return nil, true
	}
	if strings.HasPrefix(comp, "^") {
		p, ok := parsePartialSemver(comp[1:])
		if !ok {
			return nil, false
		}
		if !p.has[0] {
			return nil, true
		}
		low := semver{nums: p.nums, pre: p.pre}
		var high semver
		switch {
		case p.nums[0] > 0:
			high = semver{nums: [3]int{p.nums[0] + 1, 0, 0}, pre: []string{"0"}}
		case p.has[1] && p.nums[1] > 0:
			high = semver{nums: [3]int{0, p.nums[1] + 1, 0}, pre: []string{"0"}}
		case p.has[2]:
			high = semver{nums: [3]int{0, 0, p.nums[2] + 1}, pre: []string{"0"}}
		case p.has[1]:
			high = semver{nums: [3]int{0, 1, 0}, pre: []string{"0"}}
		default:
			high = semver{nums: [3]int{1, 0, 0}, pre: []string{"0"}}
		}
		return []semverBound{{op: ">=", ver: low}, {op: "<", ver: high}}, true
	}
	if strings.HasPrefix(comp, "~") {
		p, ok := parsePartialSemver(comp[1:])
		if !ok {
			return nil, false
		}
		if !p.has[0] {
			return nil, true
		}
		low := semver{nums: p.nums, pre: p.pre}
		var high semver
		if !p.has[1] {
			high = semver{nums: [3]int{p.nums[0] + 1, 0, 0}, pre: []string{"0"}}
		} else {
			high = semver{nums: [3]int{p.nums[0], p.nums[1] + 1, 0}, pre: []string{"0"}}
		}
		return []semverBound{{op: ">=", ver: low}, {op: "<", ver: high}}, true
	}
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(comp, op) {
			p, ok := parsePartialSemver(comp[len(op):])
			if !ok {
				return nil, false
			}
			if !p.has[0] {
				return nil, true
			}
			switch op {
			case ">=":
				return []semverBound{{op: ">=", ver: semver{nums: p.nums, pre: p.pre}}}, true
			case "<=":
				if !p.has[1] {
					return []semverBound{{op: "<", ver: semver{nums: [3]int{p.nums[0] + 1, 0, 0}, pre: []string{"0"}}}}, true
				}
				if !p.has[2] {
					return []semverBound{{op: "<", ver: semver{nums: [3]int{p.nums[0], p.nums[1] + 1, 0}, pre: []string{"0"}}}}, true
				}
				return []semverBound{{op: "<=", ver: semver{nums: p.nums, pre: p.pre}}}, true
			case ">":
				if !p.has[1] {
					return []semverBound{{op: ">=", ver: semver{nums: [3]int{p.nums[0] + 1, 0, 0}}}}, true
				}
				if !p.has[2] {
					return []semverBound{{op: ">=", ver: semver{nums: [3]int{p.nums[0], p.nums[1] + 1, 0}}}}, true
				}
				return []semverBound{{op: ">", ver: semver{nums: p.nums, pre: p.pre}}}, true
			case "<":
				if !p.has[2] {
					return []semverBound{{op: "<", ver: semver{nums: p.nums, pre: []string{"0"}}}}, true
				}
				return []semverBound{{op: "<", ver: semver{nums: p.nums, pre: p.pre}}}, true
			case "=":
				return expandExactOrXRange(p), true
			}
		}
	}
	p, ok := parsePartialSemver(comp)
	if !ok {
		return nil, false
	}
	return expandExactOrXRange(p), true
}

func expandExactOrXRange(p partialSemver) []semverBound {
	if !p.has[0] {
		return nil
	}
	if !p.has[1] {
		return []semverBound{
			{op: ">=", ver: semver{nums: [3]int{p.nums[0], 0, 0}}},
			{op: "<", ver: semver{nums: [3]int{p.nums[0] + 1, 0, 0}, pre: []string{"0"}}},
		}
	}
	if !p.has[2] {
		return []semverBound{
			{op: ">=", ver: semver{nums: [3]int{p.nums[0], p.nums[1], 0}}},
			{op: "<", ver: semver{nums: [3]int{p.nums[0], p.nums[1] + 1, 0}, pre: []string{"0"}}},
		}
	}
	return []semverBound{{op: "=", ver: semver{nums: p.nums, pre: p.pre}}}
}

var opSpaceRE = regexp.MustCompile(`([<>]=?|=|~|\^)\s+`)

func satisfiesComparatorSet(ver semver, set string) bool {
	set = strings.TrimSpace(set)
	if set == "" {
		return len(ver.pre) == 0
	}
	var bounds []semverBound
	if lo, hi, ok := strings.Cut(set, " - "); ok {
		lb, ok1 := expandComparator(">=" + strings.TrimSpace(lo))
		hb, ok2 := expandComparator("<=" + strings.TrimSpace(hi))
		if !ok1 || !ok2 {
			return false
		}
		bounds = append(bounds, lb...)
		bounds = append(bounds, hb...)
	} else {
		norm := opSpaceRE.ReplaceAllString(set, "$1")
		for _, tok := range strings.Fields(norm) {
			bs, ok := expandComparator(tok)
			if !ok {
				return false
			}
			bounds = append(bounds, bs...)
		}
	}
	for _, b := range bounds {
		c := compareSemver(ver, b.ver)
		switch b.op {
		case ">=":
			if c < 0 {
				return false
			}
		case "<=":
			if c > 0 {
				return false
			}
		case ">":
			if c <= 0 {
				return false
			}
		case "<":
			if c >= 0 {
				return false
			}
		case "=":
			if c != 0 {
				return false
			}
		}
	}
	if len(ver.pre) > 0 {
		allowed := false
		for _, b := range bounds {
			// Synthetic "< X.Y.Z-0" upper bounds exclude X.Y.Z prereleases and must not opt them in.
			if len(b.ver.pre) > 0 && !(b.op == "<" && len(b.ver.pre) == 1 && b.ver.pre[0] == "0") && b.ver.nums == ver.nums {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func satisfiesNPMRange(version, rangeExpr string) bool {
	ver, ok := parseSemver(version)
	if !ok {
		return false
	}
	for _, alt := range strings.Split(rangeExpr, "||") {
		if satisfiesComparatorSet(ver, alt) {
			return true
		}
	}
	return false
}

type packageManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

func parsePackageManifest(text string) (*packageManifest, error) {
	var m packageManifest
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}
	return &m, nil
}

func (m *packageManifest) directDeps() map[string]string {
	out := map[string]string{}
	for _, sec := range []map[string]string{m.DevDependencies, m.OptionalDependencies, m.Dependencies} {
		for k, v := range sec {
			out[k] = v
		}
	}
	return out
}

func (m *packageManifest) directSelectors() map[string]bool {
	out := map[string]bool{}
	for _, sec := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies} {
		for k, v := range sec {
			out[k+"@"+v] = true
		}
	}
	return out
}

func parseNPMSelector(sel string) (pkg, rng string, registry bool, ok bool) {
	idx := strings.LastIndex(sel, "@")
	if idx <= 0 {
		return "", "", false, false
	}
	pkg, rng = sel[:idx], sel[idx+1:]
	if strings.HasPrefix(rng, "npm:") {
		spec := strings.TrimPrefix(rng, "npm:")
		aIdx := strings.LastIndex(spec, "@")
		if aIdx <= 0 {
			return spec, "*", true, true
		}
		pkg, rng = spec[:aIdx], spec[aIdx+1:]
	}
	for _, pfx := range []string{"git+", "git://", "http://", "https://", "file:", "link:", "workspace:", "patch:", "github:"} {
		if strings.HasPrefix(rng, pfx) {
			return pkg, rng, false, true
		}
	}
	if strings.Contains(rng, "://") {
		return pkg, rng, false, true
	}
	return pkg, rng, true, true
}

func detectRegistryBase(pairs [][2]string, fallback string) string {
	for _, p := range pairs {
		pkg, resolved := p[0], p[1]
		if pkg == "" || resolved == "" {
			continue
		}
		needle := "/" + pkg + "/-/"
		if idx := strings.Index(resolved, needle); idx > 0 {
			return resolved[:idx]
		}
	}
	return fallback
}

func buildTarballURL(registryBase, pkg, upstreamTarball, shasum string, includeShasum bool) string {
	fname := path.Base(upstreamTarball)
	if i := strings.IndexByte(fname, '#'); i >= 0 {
		fname = fname[:i]
	}
	u := strings.TrimSuffix(registryBase, "/") + "/" + pkg + "/-/" + fname
	if includeShasum && shasum != "" {
		u += "#" + shasum
	}
	return u
}

func highestServedVersion(doc *npmVerdictsResponse, ranges []string) (string, npmVersionVerdict, bool) {
	var best string
	var bestSV semver
	var bestV npmVersionVerdict
	for v, vd := range doc.Versions {
		if !vd.Served {
			continue
		}
		sv, ok := parseSemver(v)
		if !ok {
			continue
		}
		matches := true
		for _, r := range ranges {
			if !satisfiesNPMRange(v, r) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if best == "" || compareSemver(sv, bestSV) > 0 {
			best, bestSV, bestV = v, sv, vd
		}
	}
	return best, bestV, best != ""
}

func newestMatchingRefusal(doc *npmVerdictsResponse, ranges []string) (string, string) {
	var best string
	var bestSV semver
	var bestReason string
	for v, vd := range doc.Versions {
		if vd.Served {
			continue
		}
		sv, ok := parseSemver(v)
		if !ok {
			continue
		}
		matches := true
		for _, r := range ranges {
			if !satisfiesNPMRange(v, r) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if best == "" || compareSemver(sv, bestSV) > 0 {
			best, bestSV, bestReason = v, sv, vd.Reason
		}
	}
	return best, bestReason
}

type yarnEntry struct {
	selectors            []string
	version              string
	resolved             string
	integrity            string
	dependencies         map[string]string
	optionalDependencies map[string]string
}

func unquoteYarn(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func splitYarnSelectors(line string) []string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuote {
			if s := unquoteYarn(cur.String()); s != "" {
				out = append(out, s)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if s := unquoteYarn(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

func splitYarnKV(line string) (string, string, bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", "", false
	}
	var key, rest string
	if s[0] == '"' {
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			return "", "", false
		}
		key = s[1 : 1+end]
		rest = strings.TrimSpace(s[2+end:])
	} else {
		var ok bool
		key, rest, ok = strings.Cut(s, " ")
		if !ok {
			return "", "", false
		}
		rest = strings.TrimSpace(rest)
	}
	return key, unquoteYarn(rest), true
}

func parseYarnLock(text string) ([]string, []*yarnEntry, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var header []string
	var entries []*yarnEntry
	var cur *yarnEntry
	submap := ""

	for _, line := range lines {
		if len(entries) == 0 && cur == nil && strings.HasPrefix(line, "__metadata:") {
			return nil, nil, fmt.Errorf("%w: yarn berry lockfile", errUnsupportedLockfile)
		}
		if len(entries) == 0 && cur == nil && (strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "") {
			header = append(header, line)
			continue
		}
		if strings.TrimSpace(line) == "" {
			if cur != nil {
				entries = append(entries, cur)
				cur = nil
				submap = ""
			}
			continue
		}
		if !strings.HasPrefix(line, " ") {
			if cur != nil {
				entries = append(entries, cur)
			}
			sels := splitYarnSelectors(line)
			if len(sels) == 0 {
				return nil, nil, fmt.Errorf("yarn.lock: empty selector line %q", line)
			}
			cur = &yarnEntry{
				selectors:            sels,
				dependencies:         map[string]string{},
				optionalDependencies: map[string]string{},
			}
			submap = ""
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "    ") && submap != "" {
			if k, v, ok := splitYarnKV(line); ok {
				switch submap {
				case "dependencies":
					cur.dependencies[k] = v
				case "optionalDependencies":
					cur.optionalDependencies[k] = v
				}
			}
			continue
		}
		if strings.HasPrefix(line, "  ") {
			trimmed := strings.TrimSpace(line)
			switch trimmed {
			case "dependencies:":
				submap = "dependencies"
			case "optionalDependencies:":
				submap = "optionalDependencies"
			default:
				submap = ""
				if k, v, ok := splitYarnKV(trimmed); ok {
					switch k {
					case "version":
						cur.version = v
					case "resolved":
						cur.resolved = v
					case "integrity":
						cur.integrity = v
					}
				}
			}
		}
	}
	if cur != nil {
		entries = append(entries, cur)
	}
	return header, entries, nil
}

var (
	yarnSafeSelectorRE = regexp.MustCompile(`^[A-Za-z0-9._/\-^~*@]+$`)
	yarnSafeDepKeyRE   = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
)

func formatYarnSelector(sel string) string {
	if strings.HasPrefix(sel, "@") || !yarnSafeSelectorRE.MatchString(sel) {
		return `"` + sel + `"`
	}
	return sel
}

func formatYarnDepKey(k string) string {
	if strings.HasPrefix(k, "@") || !yarnSafeDepKeyRE.MatchString(k) {
		return `"` + k + `"`
	}
	return k
}

func serializeYarnLock(header []string, entries []*yarnEntry) string {
	type mergeKey struct {
		pkg, version, resolved, integrity string
	}
	merged := map[mergeKey]*yarnEntry{}
	for _, e := range entries {
		pkg, _, _, _ := parseNPMSelector(e.selectors[0])
		k := mergeKey{pkg: pkg, version: e.version, resolved: e.resolved, integrity: e.integrity}
		ex, ok := merged[k]
		if !ok {
			cp := &yarnEntry{
				selectors:            append([]string(nil), e.selectors...),
				version:              e.version,
				resolved:             e.resolved,
				integrity:            e.integrity,
				dependencies:         copyStringMap(e.dependencies),
				optionalDependencies: copyStringMap(e.optionalDependencies),
			}
			merged[k] = cp
		} else {
			for _, s := range e.selectors {
				if !slices.Contains(ex.selectors, s) {
					ex.selectors = append(ex.selectors, s)
				}
			}
		}
	}
	ordered := make([]*yarnEntry, 0, len(merged))
	for _, e := range merged {
		sort.Strings(e.selectors)
		ordered = append(ordered, e)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].selectors[0] < ordered[j].selectors[0]
	})

	var out []string
	out = append(out, header...)
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) > 0 {
		out = append(out, "")
	}
	for _, e := range ordered {
		formatted := make([]string, len(e.selectors))
		for i, s := range e.selectors {
			formatted[i] = formatYarnSelector(s)
		}
		out = append(out, strings.Join(formatted, ", ")+":")
		out = append(out, fmt.Sprintf("  version %q", e.version))
		if e.resolved != "" {
			out = append(out, fmt.Sprintf("  resolved %q", e.resolved))
		}
		if e.integrity != "" {
			out = append(out, "  integrity "+e.integrity)
		}
		if len(e.dependencies) > 0 {
			out = append(out, "  dependencies:")
			for _, k := range sortedMapKeys(e.dependencies) {
				out = append(out, fmt.Sprintf("    %s %q", formatYarnDepKey(k), e.dependencies[k]))
			}
		}
		if len(e.optionalDependencies) > 0 {
			out = append(out, "  optionalDependencies:")
			for _, k := range sortedMapKeys(e.optionalDependencies) {
				out = append(out, fmt.Sprintf("    %s %q", formatYarnDepKey(k), e.optionalDependencies[k]))
			}
		}
		out = append(out, "")
	}
	return strings.Join(out, "\n")
}

func clampYarnLock(ctx context.Context, vc *verdictClient, pkgJSONText, baseLockText, headLockText string) (string, bool, []string, []string, error) {
	manifest, err := parsePackageManifest(pkgJSONText)
	if err != nil {
		return "", false, nil, nil, err
	}
	header, headEntries, err := parseYarnLock(headLockText)
	if err != nil {
		return "", false, nil, nil, err
	}
	var baseEntries []*yarnEntry
	if strings.TrimSpace(baseLockText) != "" {
		_, baseEntries, err = parseYarnLock(baseLockText)
		if err != nil {
			return "", false, nil, nil, err
		}
	}

	headBySel := map[string]*yarnEntry{}
	var regPairs [][2]string
	for _, e := range headEntries {
		for _, s := range e.selectors {
			headBySel[s] = e
			if pkg, _, reg, ok := parseNPMSelector(s); ok && reg && e.resolved != "" {
				regPairs = append(regPairs, [2]string{pkg, e.resolved})
			}
		}
	}
	baseBySel := map[string]*yarnEntry{}
	baseByPkg := map[string][]*yarnEntry{}
	for _, e := range baseEntries {
		for _, s := range e.selectors {
			baseBySel[s] = e
		}
		if pkg, _, reg, ok := parseNPMSelector(e.selectors[0]); ok && reg {
			baseByPkg[pkg] = append(baseByPkg[pkg], e)
		}
	}
	registryBase := detectRegistryBase(regPairs, "https://registry.yarnpkg.com")

	type refusalInfo struct {
		version string
		reason  string
	}
	heldSels := map[string]refusalInfo{}
	var changedSels []string
	for s, he := range headBySel {
		be := baseBySel[s]
		if be == nil || be.version != he.version {
			changedSels = append(changedSels, s)
		}
	}
	sort.Strings(changedSels)
	for _, s := range changedSels {
		pkg, _, reg, ok := parseNPMSelector(s)
		if !ok || !reg {
			continue
		}
		he := headBySel[s]
		doc, err := vc.get(ctx, pkg)
		if err != nil {
			return "", false, nil, nil, err
		}
		vd, exists := doc.Versions[he.version]
		if !exists {
			heldSels[s] = refusalInfo{version: he.version, reason: "version not listed in upstream packument"}
			continue
		}
		if !vd.Served {
			heldSels[s] = refusalInfo{version: he.version, reason: vd.Reason}
		}
	}
	if len(heldSels) == 0 {
		return "", false, nil, nil, nil
	}

	directSels := manifest.directSelectors()
	var blocking []string
	for _, ds := range sortedMapKeys(directSels) {
		if info, held := heldSels[ds]; held {
			pkg, _, _, _ := parseNPMSelector(ds)
			blocking = append(blocking, fmt.Sprintf("direct dependency %s@%s (%s): %s", pkg, info.version, ds, info.reason))
		}
	}
	if len(blocking) > 0 {
		return "", false, nil, blocking, nil
	}

	roots := sortedMapKeys(directSels)
	if len(manifest.Workspaces) > 0 && string(manifest.Workspaces) != "null" {
		referenced := map[string]bool{}
		for _, e := range headEntries {
			for dk, dv := range e.dependencies {
				referenced[dk+"@"+dv] = true
			}
			for dk, dv := range e.optionalDependencies {
				referenced[dk+"@"+dv] = true
			}
		}
		var extra []string
		for s := range headBySel {
			if !directSels[s] && !referenced[s] {
				extra = append(extra, s)
			}
		}
		sort.Strings(extra)
		roots = append(roots, extra...)
	}

	resolved := map[string]*yarnEntry{}
	var clamped []string
	var resolveErr error

	var resolveSel func(sel string)
	resolveSel = func(sel string) {
		if resolveErr != nil {
			return
		}
		if _, done := resolved[sel]; done {
			return
		}
		pkg, rng, reg, ok := parseNPMSelector(sel)
		he := headBySel[sel]
		if !ok || !reg {
			if he != nil {
				resolved[sel] = &yarnEntry{
					selectors:            []string{sel},
					version:              he.version,
					resolved:             he.resolved,
					integrity:            he.integrity,
					dependencies:         copyStringMap(he.dependencies),
					optionalDependencies: copyStringMap(he.optionalDependencies),
				}
			}
			return
		}
		if _, held := heldSels[sel]; he != nil && !held {
			entry := &yarnEntry{
				selectors:            []string{sel},
				version:              he.version,
				resolved:             he.resolved,
				integrity:            he.integrity,
				dependencies:         copyStringMap(he.dependencies),
				optionalDependencies: copyStringMap(he.optionalDependencies),
			}
			resolved[sel] = entry
		} else {
			doc, err := vc.get(ctx, pkg)
			if err != nil {
				resolveErr = err
				return
			}
			var chosen *yarnEntry
			var bestBase *yarnEntry
			var bestBaseSV semver
			for _, be := range baseByPkg[pkg] {
				if !satisfiesNPMRange(be.version, rng) {
					continue
				}
				if vd, ok := doc.Versions[be.version]; !ok || !vd.Served {
					continue
				}
				sv, ok := parseSemver(be.version)
				if !ok {
					continue
				}
				if bestBase == nil || compareSemver(sv, bestBaseSV) > 0 {
					bestBase, bestBaseSV = be, sv
				}
			}
			if bestBase != nil {
				chosen = &yarnEntry{
					selectors:            []string{sel},
					version:              bestBase.version,
					resolved:             bestBase.resolved,
					integrity:            bestBase.integrity,
					dependencies:         copyStringMap(bestBase.dependencies),
					optionalDependencies: copyStringMap(bestBase.optionalDependencies),
				}
			} else if v, vd, found := highestServedVersion(doc, []string{rng}); found {
				chosen = &yarnEntry{
					selectors:            []string{sel},
					version:              v,
					resolved:             buildTarballURL(registryBase, pkg, vd.Tarball, vd.Shasum, true),
					integrity:            vd.Integrity,
					dependencies:         copyStringMap(vd.Dependencies),
					optionalDependencies: copyStringMap(vd.OptionalDependencies),
				}
			}
			if chosen == nil {
				refVer, refReason := newestMatchingRefusal(doc, []string{rng})
				if refVer == "" {
					if info, ok := heldSels[sel]; ok {
						refVer, refReason = info.version, info.reason
					}
				}
				if refReason == "" {
					refReason = "no served version satisfies range"
				}
				blocking = append(blocking, fmt.Sprintf("%s@%s (range %q): no served version satisfies range (%s)", pkg, refVer, rng, refReason))
				return
			}
			if he != nil && he.version != chosen.version {
				clamped = append(clamped, fmt.Sprintf("%s (%s): %s -> %s", pkg, rng, he.version, chosen.version))
			}
			resolved[sel] = chosen
		}

		entry := resolved[sel]
		for _, dk := range sortedMapKeys(entry.dependencies) {
			resolveSel(dk + "@" + entry.dependencies[dk])
		}
		for _, dk := range sortedMapKeys(entry.optionalDependencies) {
			resolveSel(dk + "@" + entry.optionalDependencies[dk])
		}
	}

	for _, root := range roots {
		resolveSel(root)
	}
	if resolveErr != nil {
		return "", false, nil, nil, resolveErr
	}
	if len(blocking) > 0 {
		return "", false, nil, blocking, nil
	}
	entries := make([]*yarnEntry, 0, len(resolved))
	for _, e := range resolved {
		entries = append(entries, e)
	}
	newText := serializeYarnLock(header, entries)
	return newText, newText != headLockText, clamped, nil, nil
}

func pkgNameForLockPath(pkgPath string, meta map[string]any) (aliasName, realName string) {
	idx := strings.LastIndex(pkgPath, "node_modules/")
	if idx < 0 {
		return "", ""
	}
	aliasName = pkgPath[idx+len("node_modules/"):]
	if n, ok := meta["name"].(string); ok && n != "" {
		return aliasName, n
	}
	return aliasName, aliasName
}

func resolveNodeModulePath(pkgs map[string]any, fromPath, depName string) string {
	cur := fromPath
	for {
		var cand string
		if cur == "" {
			cand = "node_modules/" + depName
		} else {
			cand = cur + "/node_modules/" + depName
		}
		if _, ok := pkgs[cand]; ok {
			return cand
		}
		if cur == "" {
			return ""
		}
		idx := strings.LastIndex(cur, "/node_modules/")
		if idx >= 0 {
			cur = cur[:idx]
		} else {
			cur = ""
		}
	}
}

func parentRangesForLockPath(pkgs map[string]any, targetPath, aliasName string) []string {
	var ranges []string
	for ppath, raw := range pkgs {
		pmeta, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			deps, ok := pmeta[sec].(map[string]any)
			if !ok {
				continue
			}
			rng, ok := deps[aliasName].(string)
			if !ok || rng == "" {
				continue
			}
			if resolveNodeModulePath(pkgs, ppath, aliasName) == targetPath {
				if strings.HasPrefix(rng, "npm:") {
					spec := strings.TrimPrefix(rng, "npm:")
					if i := strings.LastIndex(spec, "@"); i > 0 {
						rng = spec[i+1:]
					} else {
						rng = "*"
					}
				}
				ranges = append(ranges, rng)
			}
		}
	}
	sort.Strings(ranges)
	return ranges
}

func marshalJSONNoEscape(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func clampPackageLock(ctx context.Context, vc *verdictClient, pkgJSONText, baseLockText, headLockText string) (string, bool, []string, []string, error) {
	manifest, err := parsePackageManifest(pkgJSONText)
	if err != nil {
		return "", false, nil, nil, err
	}
	var head map[string]any
	if err := json.Unmarshal([]byte(headLockText), &head); err != nil {
		return "", false, nil, nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}
	lfv, _ := head["lockfileVersion"].(float64)
	if lfv != 2 && lfv != 3 {
		return "", false, nil, nil, fmt.Errorf("%w: package-lock.json lockfileVersion %v", errUnsupportedLockfile, head["lockfileVersion"])
	}
	headPkgs, ok := head["packages"].(map[string]any)
	if !ok {
		return "", false, nil, nil, fmt.Errorf("%w: package-lock.json missing packages map", errUnsupportedLockfile)
	}

	basePkgs := map[string]any{}
	if strings.TrimSpace(baseLockText) != "" {
		var base map[string]any
		if err := json.Unmarshal([]byte(baseLockText), &base); err != nil {
			return "", false, nil, nil, fmt.Errorf("parsing base package-lock.json: %w", err)
		}
		if bp, ok := base["packages"].(map[string]any); ok {
			basePkgs = bp
		}
	}

	var regPairs [][2]string
	for p, raw := range headPkgs {
		m, ok := raw.(map[string]any)
		if !ok || p == "" {
			continue
		}
		_, realName := pkgNameForLockPath(p, m)
		if res, ok := m["resolved"].(string); ok && realName != "" && res != "" {
			regPairs = append(regPairs, [2]string{realName, res})
		}
	}
	registryBase := detectRegistryBase(regPairs, "https://registry.npmjs.org")

	baseByPkg := map[string][]map[string]any{}
	for p, raw := range basePkgs {
		m, ok := raw.(map[string]any)
		if !ok || p == "" {
			continue
		}
		_, realName := pkgNameForLockPath(p, m)
		if realName != "" {
			baseByPkg[realName] = append(baseByPkg[realName], m)
		}
	}

	direct := manifest.directDeps()

	type heldLockEntry struct {
		path      string
		aliasName string
		realName  string
		version   string
		reason    string
	}
	var paths []string
	for p := range headPkgs {
		if p != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	var held []heldLockEntry
	for _, p := range paths {
		m, ok := headPkgs[p].(map[string]any)
		if !ok {
			continue
		}
		if link, _ := m["link"].(bool); link {
			continue
		}
		ver, _ := m["version"].(string)
		if ver == "" {
			continue
		}
		if bm, ok := basePkgs[p].(map[string]any); ok {
			if bv, _ := bm["version"].(string); bv == ver {
				continue
			}
		}
		aliasName, realName := pkgNameForLockPath(p, m)
		if realName == "" {
			continue
		}
		doc, err := vc.get(ctx, realName)
		if err != nil {
			return "", false, nil, nil, err
		}
		vd, exists := doc.Versions[ver]
		if !exists {
			held = append(held, heldLockEntry{path: p, aliasName: aliasName, realName: realName, version: ver, reason: "version not listed in upstream packument"})
			continue
		}
		if !vd.Served {
			held = append(held, heldLockEntry{path: p, aliasName: aliasName, realName: realName, version: ver, reason: vd.Reason})
		}
	}
	if len(held) == 0 {
		return "", false, nil, nil, nil
	}

	var blocking []string
	for _, h := range held {
		if h.path == "node_modules/"+h.aliasName {
			if _, isDirect := direct[h.aliasName]; isDirect {
				blocking = append(blocking, fmt.Sprintf("direct dependency %s@%s: %s", h.realName, h.version, h.reason))
			}
		}
	}
	if len(blocking) > 0 {
		return "", false, nil, blocking, nil
	}

	var clamped []string
	visited := map[string]bool{}

	applyVersion := func(realName, ver string, baseMeta map[string]any, vd npmVersionVerdict, meta map[string]any) {
		meta["version"] = ver
		if baseMeta != nil {
			if res, ok := baseMeta["resolved"].(string); ok && res != "" {
				meta["resolved"] = res
			} else {
				meta["resolved"] = buildTarballURL(registryBase, realName, vd.Tarball, vd.Shasum, false)
			}
			if integ, ok := baseMeta["integrity"].(string); ok && integ != "" {
				meta["integrity"] = integ
			} else if vd.Integrity != "" {
				meta["integrity"] = vd.Integrity
			}
		} else {
			meta["resolved"] = buildTarballURL(registryBase, realName, vd.Tarball, vd.Shasum, false)
			if vd.Integrity != "" {
				meta["integrity"] = vd.Integrity
			} else {
				delete(meta, "integrity")
			}
		}
		if len(vd.Dependencies) > 0 {
			meta["dependencies"] = toAnyMap(vd.Dependencies)
		} else {
			delete(meta, "dependencies")
		}
		if len(vd.OptionalDependencies) > 0 {
			meta["optionalDependencies"] = toAnyMap(vd.OptionalDependencies)
		} else {
			delete(meta, "optionalDependencies")
		}
		if len(vd.PeerDependencies) > 0 {
			meta["peerDependencies"] = toAnyMap(vd.PeerDependencies)
		} else {
			delete(meta, "peerDependencies")
		}
	}

	pickServed := func(doc *npmVerdictsResponse, pkgPath, realName string, ranges []string) (string, map[string]any, npmVersionVerdict, bool) {
		var bestBaseMeta map[string]any
		var bestBaseVer string
		var bestBaseSV semver
		tryBase := func(bm map[string]any) {
			bv, _ := bm["version"].(string)
			if bv == "" {
				return
			}
			vd, ok := doc.Versions[bv]
			if !ok || !vd.Served {
				return
			}
			for _, r := range ranges {
				if !satisfiesNPMRange(bv, r) {
					return
				}
			}
			sv, ok := parseSemver(bv)
			if !ok {
				return
			}
			if bestBaseVer == "" || compareSemver(sv, bestBaseSV) > 0 {
				bestBaseVer, bestBaseSV, bestBaseMeta = bv, sv, bm
			}
		}
		if bm, ok := basePkgs[pkgPath].(map[string]any); ok {
			tryBase(bm)
		}
		for _, bm := range baseByPkg[realName] {
			tryBase(bm)
		}
		if bestBaseVer != "" {
			return bestBaseVer, bestBaseMeta, doc.Versions[bestBaseVer], true
		}
		v, vd, ok := highestServedVersion(doc, ranges)
		if !ok {
			return "", nil, npmVersionVerdict{}, false
		}
		return v, nil, vd, true
	}

	var ensureDeps func(parentPath string) error
	ensureDeps = func(parentPath string) error {
		if visited[parentPath] {
			return nil
		}
		visited[parentPath] = true
		pmeta, ok := headPkgs[parentPath].(map[string]any)
		if !ok {
			return nil
		}
		for _, sec := range []string{"dependencies", "optionalDependencies"} {
			deps, ok := pmeta[sec].(map[string]any)
			if !ok {
				continue
			}
			for _, depName := range sortedMapKeys(deps) {
				rng, _ := deps[depName].(string)
				if rng == "" {
					continue
				}
				realName := depName
				if strings.HasPrefix(rng, "npm:") {
					spec := strings.TrimPrefix(rng, "npm:")
					if i := strings.LastIndex(spec, "@"); i > 0 {
						realName, rng = spec[:i], spec[i+1:]
					} else {
						realName, rng = spec, "*"
					}
				}
				resolvedPath := resolveNodeModulePath(headPkgs, parentPath, depName)
				if resolvedPath != "" {
					if em, ok := headPkgs[resolvedPath].(map[string]any); ok {
						if ev, _ := em["version"].(string); ev != "" && satisfiesNPMRange(ev, rng) {
							continue
						}
					}
				}
				doc, err := vc.get(ctx, realName)
				if err != nil {
					return err
				}
				targetPath := "node_modules/" + depName
				if _, occupied := headPkgs[targetPath]; occupied {
					targetPath = parentPath + "/node_modules/" + depName
				}
				ver, baseMeta, vd, found := pickServed(doc, targetPath, realName, []string{rng})
				if !found {
					refVer, refReason := newestMatchingRefusal(doc, []string{rng})
					if refReason == "" {
						refReason = "no served version satisfies range"
					}
					blocking = append(blocking, fmt.Sprintf("%s@%s (range %q): no served version satisfies range (%s)", realName, refVer, rng, refReason))
					continue
				}
				entry := map[string]any{}
				if realName != depName {
					entry["name"] = realName
				}
				applyVersion(realName, ver, baseMeta, vd, entry)
				headPkgs[targetPath] = entry
				if err := ensureDeps(targetPath); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, h := range held {
		ranges := parentRangesForLockPath(headPkgs, h.path, h.aliasName)
		if len(ranges) == 0 {
			ranges = []string{"*"}
		}
		doc, err := vc.get(ctx, h.realName)
		if err != nil {
			return "", false, nil, nil, err
		}
		chosen, baseMeta, vd, found := pickServed(doc, h.path, h.realName, ranges)
		if !found {
			blocking = append(blocking, fmt.Sprintf("%s@%s (ranges %q): no served version satisfies range (%s)", h.realName, h.version, strings.Join(ranges, ", "), h.reason))
			continue
		}
		meta := headPkgs[h.path].(map[string]any)
		applyVersion(h.realName, chosen, baseMeta, vd, meta)
		clamped = append(clamped, fmt.Sprintf("%s (%s): %s -> %s", h.realName, strings.Join(ranges, ", "), h.version, chosen))
		if err := ensureDeps(h.path); err != nil {
			return "", false, nil, nil, err
		}
	}

	if len(blocking) > 0 {
		return "", false, nil, blocking, nil
	}

	reachable := map[string]bool{"": true}
	queue := []string{""}
	for p, raw := range headPkgs {
		if p != "" && !strings.Contains(p, "node_modules/") {
			if _, ok := raw.(map[string]any); ok {
				reachable[p] = true
				queue = append(queue, p)
			}
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		pmeta, ok := headPkgs[cur].(map[string]any)
		if !ok {
			continue
		}
		for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
			deps, ok := pmeta[sec].(map[string]any)
			if !ok {
				continue
			}
			for depName := range deps {
				if target := resolveNodeModulePath(headPkgs, cur, depName); target != "" && !reachable[target] {
					reachable[target] = true
					queue = append(queue, target)
				}
			}
		}
	}
	for p := range headPkgs {
		if !reachable[p] {
			delete(headPkgs, p)
		}
	}

	if legacy, ok := head["dependencies"].(map[string]any); ok {
		for depName := range legacy {
			if _, exists := headPkgs["node_modules/"+depName]; !exists {
				delete(legacy, depName)
			}
		}
		for p, raw := range headPkgs {
			if !strings.HasPrefix(p, "node_modules/") || strings.Contains(strings.TrimPrefix(p, "node_modules/"), "/node_modules/") {
				continue
			}
			pm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			depName := strings.TrimPrefix(p, "node_modules/")
			lm, ok := legacy[depName].(map[string]any)
			if !ok {
				lm = map[string]any{}
				legacy[depName] = lm
			}
			if v, ok := pm["version"].(string); ok {
				lm["version"] = v
			}
			if res, ok := pm["resolved"].(string); ok {
				lm["resolved"] = res
			}
			if integ, ok := pm["integrity"].(string); ok {
				lm["integrity"] = integ
			}
			if deps, ok := pm["dependencies"].(map[string]any); ok {
				lm["requires"] = deps
			} else {
				delete(lm, "requires")
			}
		}
	}

	out, err := marshalJSONNoEscape(head)
	if err != nil {
		return "", false, nil, nil, err
	}
	return out, out != headLockText, clamped, nil, nil
}

func copyStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
