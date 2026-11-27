package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type githubApp struct {
	api            string
	appID          string
	installationID string
	key            *rsa.PrivateKey
	client         *http.Client
	token          string
}

func parseAppKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("the App private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the App private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the App private key is not RSA")
	}
	return rk, nil
}

// The issued time sits a minute back to absorb clock skew.
func (a *githubApp) jwt(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.appID,
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

func (a *githubApp) do(ctx context.Context, method, url, auth string, body []byte) (*http.Response, error) {
	return a.doAccept(ctx, method, url, auth, "application/vnd.github+json", body)
}

func (a *githubApp) doAccept(ctx context.Context, method, url, auth, accept string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.Do(req)
}

func (a *githubApp) mint(ctx context.Context) error {
	return a.mintWithPermissions(ctx, map[string]string{"contents": "read"})
}

func (a *githubApp) mintWithPermissions(ctx context.Context, permissions map[string]string) error {
	jwt, err := a.jwt(time.Now())
	if err != nil {
		return err
	}
	reqBody, err := json.Marshal(map[string]any{"permissions": permissions})
	if err != nil {
		return err
	}
	resp, err := a.do(ctx, http.MethodPost, a.api+"/app/installations/"+a.installationID+"/access_tokens",
		"Bearer "+jwt, reqBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("minting an installation token: %s %s", resp.Status, strings.TrimSpace(string(body[:min(len(body), 512)])))
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.Token == "" {
		return fmt.Errorf("minting an installation token: no token in the answer")
	}
	a.token = tok.Token
	return nil
}

type repository struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Size          int    `json:"size"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (a *githubApp) repositories(ctx context.Context, owner string) ([]repository, error) {
	var out []repository
	for page := 1; ; page++ {
		resp, err := a.do(ctx, http.MethodGet, fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", a.api, page), "token "+a.token, nil)
		if err != nil {
			return nil, err
		}
		var body struct {
			Total        int          `json:"total_count"`
			Repositories []repository `json:"repositories"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("listing the installation's repositories: %s", resp.Status)
		}
		if err != nil {
			return nil, fmt.Errorf("listing the installation's repositories: %w", err)
		}
		for _, r := range body.Repositories {
			if strings.EqualFold(r.Owner.Login, owner) && !r.Archived && !r.Disabled {
				out = append(out, r)
			}
		}
		if len(body.Repositories) == 0 || page*100 >= body.Total {
			return out, nil
		}
	}
}

var errEmptyRepository = errors.New("the repository has no commit to read")

func (a *githubApp) fetch(ctx context.Context, r repository, dest string) error {
	resp, err := a.do(ctx, http.MethodGet, a.api+"/repos/"+r.FullName+"/tarball/"+r.DefaultBranch, "token "+a.token, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// GitHub answers 404 both for a repository with no commit and for one
	// the token cannot read; only the first is skipped.
	if resp.StatusCode == http.StatusNotFound && r.Size == 0 {
		return errEmptyRepository
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: tarball: %s", r.FullName, resp.Status)
	}
	if err := extractTarball(resp.Body, dest); err != nil {
		return fmt.Errorf("%s: %w", r.FullName, err)
	}
	return nil
}

func extractTarball(body io.Reader, dest string) error {
	gz, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// GitHub roots every entry in one <owner>-<repo>-<sha>/ directory.
		_, rel, _ := strings.Cut(h.Name, "/")
		rel = path.Clean("/" + rel)[1:]
		if rel == "" {
			continue
		}
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("tarball entry %q leaves the checkout", h.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		}
	}
}

type pullRequest struct {
	Number int `json:"number"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
	Head pullRef `json:"head"`
	Base pullRef `json:"base"`
}

type pullRef struct {
	Ref  string `json:"ref"`
	SHA  string `json:"sha"`
	Repo *struct {
		FullName string `json:"full_name"`
	} `json:"repo"`
}

type pullFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
}

type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

var errRefMoved = errors.New("branch ref moved before update")

func escapeGitHubPath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = neturl.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}

func readGitHubJSON(resp *http.Response, wantStatus int, action string, dst any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("%s: %s %s", action, resp.Status, strings.TrimSpace(string(body[:min(len(body), 512)])))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func (a *githubApp) openPullRequests(ctx context.Context, fullName string) ([]pullRequest, error) {
	var out []pullRequest
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/repos/%s/pulls?state=open&per_page=100&page=%d", a.api, fullName, page)
		resp, err := a.do(ctx, http.MethodGet, u, "token "+a.token, nil)
		if err != nil {
			return nil, err
		}
		var batch []pullRequest
		if err := readGitHubJSON(resp, http.StatusOK, fullName+": listing open pull requests", &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			return out, nil
		}
	}
}

func (a *githubApp) pullRequestFiles(ctx context.Context, fullName string, number int) ([]pullFile, error) {
	var out []pullFile
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/repos/%s/pulls/%d/files?per_page=100&page=%d", a.api, fullName, number, page)
		resp, err := a.do(ctx, http.MethodGet, u, "token "+a.token, nil)
		if err != nil {
			return nil, err
		}
		var batch []pullFile
		if err := readGitHubJSON(resp, http.StatusOK, fmt.Sprintf("%s#%d: listing files", fullName, number), &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			return out, nil
		}
	}
}

func (a *githubApp) fileContent(ctx context.Context, fullName, filePath, ref string) ([]byte, error) {
	u := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", a.api, fullName, escapeGitHubPath(filePath), neturl.QueryEscape(ref))
	resp, err := a.doAccept(ctx, http.MethodGet, u, "token "+a.token, "application/vnd.github.raw+json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s:%s@%s: %s %s", fullName, filePath, ref, resp.Status, strings.TrimSpace(string(b[:min(len(b), 512)])))
	}
	return b, nil
}

func (a *githubApp) issueComments(ctx context.Context, fullName string, number int) ([]issueComment, error) {
	var out []issueComment
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100&page=%d", a.api, fullName, number, page)
		resp, err := a.do(ctx, http.MethodGet, u, "token "+a.token, nil)
		if err != nil {
			return nil, err
		}
		var batch []issueComment
		if err := readGitHubJSON(resp, http.StatusOK, fmt.Sprintf("%s#%d: listing comments", fullName, number), &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			return out, nil
		}
	}
}

func (a *githubApp) createIssueComment(ctx context.Context, fullName string, number int, bodyText string) error {
	payload, err := json.Marshal(map[string]string{"body": bodyText})
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", a.api, fullName, number)
	resp, err := a.do(ctx, http.MethodPost, u, "token "+a.token, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s#%d: creating comment: %s %s", fullName, number, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (a *githubApp) updateIssueComment(ctx context.Context, fullName string, commentID int64, bodyText string) error {
	payload, err := json.Marshal(map[string]string{"body": bodyText})
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/repos/%s/issues/comments/%d", a.api, fullName, commentID)
	resp, err := a.do(ctx, http.MethodPatch, u, "token "+a.token, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s comment %d: updating comment: %s %s", fullName, commentID, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (a *githubApp) commitFiles(ctx context.Context, fullName, headRef, headSHA, message string, files map[string]string) (string, error) {
	resp, err := a.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/git/commits/%s", a.api, fullName, headSHA), "token "+a.token, nil)
	if err != nil {
		return "", err
	}
	var headCommit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := readGitHubJSON(resp, http.StatusOK, fmt.Sprintf("%s: reading head commit %s", fullName, headSHA), &headCommit); err != nil {
		return "", err
	}
	if headCommit.Tree.SHA == "" {
		return "", fmt.Errorf("%s: reading head commit %s: no tree sha", fullName, headSHA)
	}

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(paths))
	for _, p := range paths {
		payload, err := json.Marshal(map[string]string{"content": files[p], "encoding": "utf-8"})
		if err != nil {
			return "", err
		}
		bresp, err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/git/blobs", a.api, fullName), "token "+a.token, payload)
		if err != nil {
			return "", err
		}
		var blob struct {
			SHA string `json:"sha"`
		}
		if err := readGitHubJSON(bresp, http.StatusCreated, fmt.Sprintf("%s: creating blob for %s", fullName, p), &blob); err != nil {
			return "", err
		}
		if blob.SHA == "" {
			return "", fmt.Errorf("%s: creating blob for %s: no sha", fullName, p)
		}
		entries = append(entries, treeEntry{Path: p, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}

	treePayload, err := json.Marshal(map[string]any{"base_tree": headCommit.Tree.SHA, "tree": entries})
	if err != nil {
		return "", err
	}
	tresp, err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/git/trees", a.api, fullName), "token "+a.token, treePayload)
	if err != nil {
		return "", err
	}
	var newTree struct {
		SHA string `json:"sha"`
	}
	if err := readGitHubJSON(tresp, http.StatusCreated, fullName+": creating tree", &newTree); err != nil {
		return "", err
	}
	if newTree.SHA == "" {
		return "", fmt.Errorf("%s: creating tree: no sha", fullName)
	}

	commitPayload, err := json.Marshal(map[string]any{
		"message": message,
		"tree":    newTree.SHA,
		"parents": []string{headSHA},
	})
	if err != nil {
		return "", err
	}
	cresp, err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/git/commits", a.api, fullName), "token "+a.token, commitPayload)
	if err != nil {
		return "", err
	}
	var newCommit struct {
		SHA string `json:"sha"`
	}
	if err := readGitHubJSON(cresp, http.StatusCreated, fullName+": creating commit", &newCommit); err != nil {
		return "", err
	}
	if newCommit.SHA == "" {
		return "", fmt.Errorf("%s: creating commit: no sha", fullName)
	}

	refPayload, err := json.Marshal(map[string]any{"sha": newCommit.SHA, "force": false})
	if err != nil {
		return "", err
	}
	rresp, err := a.do(ctx, http.MethodPatch, fmt.Sprintf("%s/repos/%s/git/refs/heads/%s", a.api, fullName, escapeGitHubPath(headRef)), "token "+a.token, refPayload)
	if err != nil {
		return "", err
	}
	defer rresp.Body.Close()
	if rresp.StatusCode == http.StatusConflict || rresp.StatusCode == http.StatusUnprocessableEntity {
		return "", errRefMoved
	}
	if rresp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(rresp.Body, 512))
		return "", fmt.Errorf("%s: updating ref %s: %s %s", fullName, headRef, rresp.Status, strings.TrimSpace(string(b)))
	}
	return newCommit.SHA, nil
}
