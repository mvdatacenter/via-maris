package main

import (
	"net/http"
	"testing"
	"time"
)

// The GET Object example of AWS's Signature Version 4 documentation.
func TestSignMatchesTheReferenceExample(t *testing.T) {
	s := &objectStore{region: "us-east-1", accessKey: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	s.sign(req, emptySHA256, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization\n got %s\nwant %s", got, want)
	}
}

func TestS3Escape(t *testing.T) {
	if got := s3Escape("records/2026-10-25/a b+c~.ndjson"); got != "records/2026-10-25/a%20b%2Bc~.ndjson" {
		t.Errorf("s3Escape = %s", got)
	}
}

// The ListObjectsV2 example of AWS's Signature Version 4 documentation, so
// the signed query is in canonical form.
func TestSignedListQueryMatchesTheReferenceExample(t *testing.T) {
	s := &objectStore{region: "us-east-1", accessKey: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	s.sign(req, emptySHA256, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization\n got %s\nwant %s", got, want)
	}
	if got := s3QueryEscape("records/2026-10-25/150405.000000000"); got != "records%2F2026-10-25%2F150405.000000000" {
		t.Errorf("s3QueryEscape = %s", got)
	}
}
