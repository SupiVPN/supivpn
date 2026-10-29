// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func testToken(t *testing.T) (string, [32]byte) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest, err := TokenDigest([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	return token, digest
}

func TestMetricsDisabledAndConfiguration(t *testing.T) {
	for _, c := range []*Config{nil, {}, {Listen: "bad", TLSCertificate: "absent", BearerTokenSecretARN: "absent"}} {
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(true); err != nil {
			t.Fatal(err)
		}
		close, err := Listen(context.Background(), c, nil)
		if err != nil {
			t.Fatal("disabled metrics opened files/listener")
		}
		close()
	}
	valid := Config{Enabled: true, Listen: "127.0.0.1:9098", TLSCertificate: "/cert", TLSPrivateKey: "/key"}
	if valid.Validate(false) != nil {
		t.Fatal("valid TLS config rejected")
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.TLSPrivateKey = "" }, func(c *Config) { c.TLSCertificate = "relative" },
		func(c *Config) { c.Listen = ":9098" }, func(c *Config) { c.Listen = "example.test:9098" },
		func(c *Config) { c.Listen = "127.0.0.1:0" }, func(c *Config) { c.BearerTokenSecretARN = "secret" },
	} {
		c := valid
		edit(&c)
		if c.Validate(false) == nil {
			t.Fatal("unsafe VM config accepted")
		}
	}
	if valid.Validate(true) == nil {
		t.Fatal("Lambda accepted VM configuration")
	}
	lambda := Config{Enabled: true, BearerTokenSecretARN: "arn-placeholder"}
	if lambda.Validate(true) != nil {
		t.Fatal("Lambda secret source rejected")
	}
	lambda.BearerTokenSecretARN = ""
	if lambda.Validate(true) == nil {
		t.Fatal("Lambda accepted no authentication")
	}
}

func TestMetricsAuthenticationPrecedesCollection(t *testing.T) {
	token, digest := testToken(t)
	count := 0
	h := PublicRoute("", http.NotFoundHandler(), Protect(digest, Handler(func(context.Context) ([]Family, error) { count++; return nil, nil })))
	for _, tc := range []struct {
		url, method string
		headers     []string
		status      int
	}{
		{"https://vpn.test/metrics", "GET", nil, 401},
		{"https://vpn.test/metrics", "GET", []string{"Bearer " + strings.Repeat("x", 43)}, 401},
		{"https://vpn.test/metrics", "GET", []string{"Bearer " + token, "Bearer " + token}, 401},
		{"https://vpn.test/metrics", "GET", []string{"Bearer " + token + ",Bearer " + token}, 401},
		{"http://vpn.test/metrics", "GET", []string{"Bearer " + token}, 401},
		{"https://vpn.test/metrics", "POST", []string{"Bearer " + token}, 405},
		{"https://vpn.test/metrics?token=" + token, "GET", []string{"Bearer " + token}, 400},
		{"https://vpn.test/metrics?", "GET", []string{"Bearer " + token}, 400},
		{"https://vpn.test/%6detrics", "GET", []string{"Bearer " + token}, 404},
		{"https://vpn.test/metrics/", "GET", []string{"Bearer " + token}, 404},
		{"https://vpn.test/metrics", "GET", []string{"Bearer " + token}, 200},
	} {
		r := httptest.NewRequest(tc.method, tc.url, nil)
		for _, v := range tc.headers {
			r.Header.Add("Authorization", v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status %d, want %d", w.Code, tc.status)
		}
		if strings.Contains(w.Body.String(), token) {
			t.Fatal("credential leaked")
		}
	}
	if count != 1 {
		t.Fatalf("unauthorized or malformed request collected metrics: %d", count)
	}
	h = PublicRoute("", http.NotFoundHandler(), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	if w.Code != 404 {
		t.Fatal("disabled endpoint exposed")
	}
	for _, raw := range []string{"", token + "\n", "Bearer " + token, token + "=", strings.Repeat("x", 44)} {
		if _, err := TokenDigest([]byte(raw)); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
}

func TestMetricsCollectionBoundedAndOpaque(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var count atomic.Int64
	h := Handler(func(ctx context.Context) ([]Family, error) {
		count.Add(1)
		close(entered)
		<-release
		if _, ok := ctx.Deadline(); !ok {
			t.Error("missing collection deadline")
		}
		return nil, errors.New("private database details")
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
		if w.Code != 503 || strings.Contains(w.Body.String(), "private") {
			t.Error("collector failure exposed")
		}
	}()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	close(release)
	<-done
	if w.Code != 503 || count.Load() != 1 {
		t.Fatal("parallel collection not bounded")
	}
}

func TestMetricsPrometheusExposition(t *testing.T) {
	h := Handler(func(context.Context) ([]Family, error) {
		return []Family{Gauge("supivpn_test_sessions", "Synthetic snapshot.", 3)}, nil
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://vpn.test/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "# TYPE supivpn_test_sessions gauge") || !strings.Contains(w.Body.String(), "supivpn_test_sessions 3") || !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatal("invalid Prometheus response")
	}
	for _, r := range []*http.Request{httptest.NewRequest("GET", "http://vpn.test/metrics", nil), httptest.NewRequest("GET", "https://vpn.test/metrics", strings.NewReader("body"))} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("unsafe request accepted")
		}
	}
}
