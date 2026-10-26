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
	"os"
	"path"
	"path/filepath"
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
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", auth)
	return a.client.Do(req)
}

func (a *githubApp) mint(ctx context.Context) error {
	jwt, err := a.jwt(time.Now())
	if err != nil {
		return err
	}
	resp, err := a.do(ctx, http.MethodPost, a.api+"/app/installations/"+a.installationID+"/access_tokens",
		"Bearer "+jwt, []byte(`{"permissions":{"contents":"read"}}`))
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
