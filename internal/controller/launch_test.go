// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/saml"
)

// Any backend call panics: launching must work without database operations,
// including readiness, and must never establish an authenticated session.
type launchUnusedBackend struct{ Backend }

func launchTestHandler(t *testing.T, prefix string, enabled bool) http.Handler {
	t.Helper()
	origin, _ := url.Parse("https://vpn.example.test" + prefix)
	sp := &saml.ServiceProvider{EntityID: origin.String() + "/saml/metadata", AcsURL: *origin.JoinPath("saml/acs")}
	c := Config{Policy: Policy{SAMLGroupsAttribute: "groups", Groups: []Group{{GroupName: "admins-vpn", Priority: 10}}}, PendingSeconds: 60, SessionSeconds: 43200}
	var downloads []ProfileDownloads
	if enabled {
		downloads = append(downloads, ProfileDownloads{Backend: launchUnusedBackend{}, Issue: func(context.Context) ([]byte, error) {
			t.Fatal("launch accessed the profile issuer")
			return nil, nil
		}})
	}
	a, err := New(c, origin, sp, launchUnusedBackend{}, time.Now, downloads...)
	if err != nil {
		t.Fatal(err)
	}
	return a.Handler()
}

func TestProfileLaunchIsNavigationOnly(t *testing.T) {
	for _, prefix := range []string{"", "/supivpn"} {
		t.Run("prefix="+prefix, func(t *testing.T) {
			h := launchTestHandler(t, prefix, true)
			for _, body := range []string{
				"", "not XML or a form", "SAMLResponse=invalid&RelayState=https://evil.example.test/",
				"SAMLResponse=first&SAMLResponse=second&RelayState=profile_forged&RelayState=//evil.example.test",
				"SAMLResponse=%GG&username=administrator&groups=admins-vpn",
			} {
				r := httptest.NewRequest(http.MethodPost, "https://vpn.example.test"+prefix+"/saml/launch", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("X-Forwarded-Host", "evil.example.test")
				r.Header.Set("Referer", "https://evil.example.test/")
				r.AddCookie(&http.Cookie{Name: "__Host-supivpn-forged", Value: "ignored"})
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusSeeOther || w.Header().Get("Location") != prefix+"/profile" ||
					w.Body.Len() != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("Content-Disposition") != "" {
					t.Fatal("launch authenticated, reflected input, or changed navigation")
				}
				if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" ||
					w.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
					t.Fatal("launch security headers missing")
				}
			}
		})
	}
}

type launchBrokenBody struct{}

func (launchBrokenBody) Read([]byte) (int, error) { return 0, errors.New("synthetic-read-failure") }
func (launchBrokenBody) Close() error           { return nil }

func TestProfileLaunchRejectsInvalidRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"get", func(r *http.Request) { r.Method = "GET" }, 405},
		{"head", func(r *http.Request) { r.Method = "HEAD" }, 405},
		{"put", func(r *http.Request) { r.Method = "PUT" }, 405},
		{"query", func(r *http.Request) { r.URL.RawQuery = "RelayState=https://evil.example.test" }, 400},
		{"empty-query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"wrong-host", func(r *http.Request) { r.Host = "evil.example.test" }, 400},
		{"no-tls", func(r *http.Request) { r.TLS = nil }, 400},
		{"encoded-path", func(r *http.Request) { r.URL.RawPath = "/supivpn/saml/%6caunch" }, 404},
		{"read-error", func(r *http.Request) { r.Body = launchBrokenBody{} }, 400},
		{"oversized", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))
			r.ContentLength = (1 << 20) + 1
		}, 413},
		{"oversized-unknown-length", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))
			r.ContentLength = -1
		}, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://vpn.example.test/supivpn/saml/launch", strings.NewReader("ignored"))
			tc.edit(r)
			w := httptest.NewRecorder()
			launchTestHandler(t, "/supivpn", true).ServeHTTP(w, r)
			if w.Code != tc.want || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 ||
				strings.Contains(w.Body.String(), "synthetic-read-failure") {
				t.Fatalf("unexpected rejection: status=%d, want=%d", w.Code, tc.want)
			}
			if tc.want == 405 && w.Header().Get("Allow") != "POST" {
				t.Fatal("missing allowed method")
			}
		})
	}
	t.Run("disabled", func(t *testing.T) {
		w := httptest.NewRecorder()
		launchTestHandler(t, "/supivpn", false).ServeHTTP(w, httptest.NewRequest("POST", "https://vpn.example.test/supivpn/saml/launch", nil))
		if w.Code != 404 || w.Header().Get("Location") != "" {
			t.Fatal("launch available while profile downloads disabled")
		}
	})
}
