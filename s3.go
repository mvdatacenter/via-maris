package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type objectStore struct {
	endpoint, region, bucket string
	accessKey, secretKey     string
	client                   *http.Client
}

func newObjectStore(s Store, client *http.Client) *objectStore {
	return &objectStore{
		endpoint:  s.Endpoint,
		region:    s.Region,
		bucket:    s.Bucket,
		accessKey: os.Getenv(s.AccessKeyIDEnv),
		secretKey: os.Getenv(s.SecretAccessKeyEnv),
		client:    client,
	}
}

func (s *objectStore) objectURL(key string) string {
	return s.endpoint + "/" + s3Escape(s.bucket) + "/" + s3Escape(key)
}

func (s *objectStore) get(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	s.sign(req, emptySHA256, time.Now())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s/%s: %s %s", s.bucket, key, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

func (s *objectStore) put(ctx context.Context, key, contentType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	sum := sha256.Sum256(body)
	s.sign(req, hex.EncodeToString(sum[:]), time.Now())
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("PUT %s/%s: %s %s", s.bucket, key, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (s *objectStore) sign(req *http.Request, payloadHash string, t time.Time) {
	stamp := t.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	headers := map[string]string{"host": req.URL.Host}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") || lower == "range" || lower == "content-type" {
			headers[lower] = strings.TrimSpace(strings.Join(vs, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + headers[n] + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonHeaders.String(),
		signed,
		payloadHash,
	}, "\n")
	scope := day + "/" + s.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + sha256Hex(canonical)

	key := hmacSHA256([]byte("AWS4"+s.secretKey), day)
	for _, part := range []string{s.region, "s3", "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signed, sig))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func s3Escape(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-_.~/", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
