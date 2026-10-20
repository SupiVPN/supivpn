// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type credentialsFunc func(context.Context) (aws.Credentials, error)

func (f credentialsFunc) Retrieve(ctx context.Context) (aws.Credentials, error) { return f(ctx) }
func TestSignedRequestsUseCurrentCredentialsAndExactBody(t *testing.T) {
	creds := aws.Credentials{AccessKeyID: "TESTONLY", SecretAccessKey: "synthetic-test-value", SessionToken: "test-session-1"}
	var mu sync.Mutex
	count := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		count++
		body, _ := io.ReadAll(r.Body)
		hash := sha256.Sum256(body)
		signed := r.Header.Get("Authorization")
		stamp, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err != nil {
			t.Error("missing signing timestamp")
		}
		if r.Method != "POST" || r.URL.Path != "/agent/v1/register" || r.Header.Get("X-Amz-Security-Token") != creds.SessionToken {
			t.Error("incorrect signed request")
		}
		var q Request
		if json.Unmarshal(body, &q) != nil || q.CID == nil || *q.CID != 0 || q.KID == nil || *q.KID != 0 {
			t.Error("zero connection IDs were omitted")
		}
		r.URL.Scheme, r.URL.Host = "https", r.Host
		// net/http adds this unsigned transport header after signing.
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Authorization")
		if v4.NewSigner().SignHTTP(r.Context(), creds, r, hex.EncodeToString(hash[:]), "execute-api", "eu-central-1", stamp) != nil ||
			signed != r.Header.Get("Authorization") {
			t.Error("signature/body mismatch")
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	client, _ := New(s.URL, s.Client().Transport, SigV4("eu-central-1", credentialsFunc(func(context.Context) (aws.Credentials, error) { mu.Lock(); defer mu.Unlock(); return creds, nil })))
	defer client.Close()
	zero := int64(0)
	for _, token := range []string{"test-session-1", "test-session-2"} {
		mu.Lock()
		creds.SessionToken = token
		mu.Unlock()
		if _, err := client.Call(context.Background(), "register", Request{Generation: "g1", CID: &zero, KID: &zero, Ticket: strings.Repeat("a", 43)}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatal("requests missing")
	}
}

func TestClientRejectsRedirectsAndInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body, media string
		expected    int
	}{
		{"redirect", 302, "", "", 302},
		{"forbidden", 403, "private diagnostics", "text/plain", 403},
		{"throttled", 429, "", "", 429},
		{"HTML", 200, "<html>challenge</html>", "text/html", 502},
		{"oversize", 200, strings.Repeat(" ", 8193), "application/json", 502},
		{"trailing", 200, "{} {}", "application/json", 502},
		{"unknown", 200, `{"extra":true}`, "application/json", 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			var mu sync.Mutex
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests++
				mu.Unlock()
				w.Header().Set("Location", "/elsewhere")
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			client, _ := New(s.URL, s.Client().Transport, nil)
			defer client.Close()
			_, err := client.Call(context.Background(), "fetch", Request{})
			if err == nil || Status(err) != tc.expected || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe error handling", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if requests != 1 {
				t.Fatal("followed redirect")
			}
		})
	}
}
func TestClientCancellationAndURLValidation(t *testing.T) {
	for _, raw := range []string{"http://example.test", "https://u:p@example.test", "https://example.test/", "https://example.test?", "https://example.test/path", "https://example.test#fragment"} {
		if _, err := New(raw, nil, nil); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := New("https://example.test", nil, nil)
	defer c.Close()
	if _, err := c.Call(ctx, "fetch", Request{}); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
