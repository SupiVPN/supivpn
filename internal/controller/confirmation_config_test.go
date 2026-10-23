// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type confirmationConfigBackend struct {
	confirmationBackend
	completions int
}

func (b *confirmationConfigBackend) Complete(context.Context, Pending, Authorization) error {
	b.completions++
	return ErrLoginExpired
}

func TestVPNConfirmationConfiguration(t *testing.T) {
	for _, name := range []string{"omitted", "enabled", "disabled"} {
		t.Run(name, func(t *testing.T) {
			fixture, _ := confirmationController(t, "/supivpn")
			configuration := fixture.config
			if name != "omitted" {
				enabled := name == "enabled"
				configuration.VPNLoginConfirmation = &enabled
			}
			backend := &confirmationConfigBackend{}
			control, err := New(configuration, fixture.origin, fixture.sp, backend, nil)
			if err != nil {
				t.Fatal(err)
			}
			handler := control.Handler()
			target := fixture.origin.String() + "/login/test-ticket"
			request := httptest.NewRequest(http.MethodGet, target, nil)
			// An existing confirmation cookie must never become a SAML credential.
			oldToken, err := randomToken()
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(&http.Cookie{Name: ConfirmationCookieName("test-ticket"), Value: oldToken})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if backend.completions != 0 {
				t.Fatal("login navigation attempted authorization")
			}
			if name != "disabled" {
				if response.Code != http.StatusOK || backend.starts != 0 || response.Header().Get("Location") != "" {
					t.Fatal("default or enabled confirmation started SAML on navigation")
				}
				query := httptest.NewRecorder()
				handler.ServeHTTP(query, httptest.NewRequest(http.MethodGet, target+"?vpn_login_confirmation=false", nil))
				if query.Code != http.StatusNotFound || backend.starts != 0 {
					t.Fatal("request query bypassed configured confirmation")
				}
				return
			}
			if response.Code != http.StatusFound || backend.starts != 1 {
				t.Fatal("explicit opt-out did not start SAML")
			}
			redirect, err := url.Parse(response.Header().Get("Location"))
			if err != nil || redirect.Host != "idp.example.test" || redirect.Query().Get("RelayState") != "test-ticket" || redirect.Query().Get("SAMLRequest") == "" {
				t.Fatal("direct login lost its IdP or request correlation")
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("direct login must issue only its independent SAML cookie")
			}
			cookie := cookies[0]
			if cookie.Name != CookieName("test-ticket") || !validConfirmationToken(cookie.Value) || cookie.Value == oldToken ||
				!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Domain != "" || cookie.Path != "/" ||
				backend.hash != sha256.Sum256([]byte(cookie.Value)) {
				t.Fatal("direct login browser binding or cookie scope is unsafe")
			}
			originalHash := backend.hash
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				refused := httptest.NewRecorder()
				handler.ServeHTTP(refused, httptest.NewRequest(method, target, nil))
				want := http.StatusConflict
				if method == http.MethodPost {
					want = http.StatusMethodNotAllowed
					if refused.Header().Get("Allow") != "GET" {
						t.Fatal("disabled confirmation advertised POST support")
					}
				}
				if refused.Code != want || backend.starts != 1 || backend.hash != originalHash || backend.completions != 0 || refused.Header().Get("Location") != "" || len(refused.Result().Cookies()) != 0 {
					t.Fatal("replayed or unsupported direct login changed SAML state")
				}
			}
		})
	}
}

func TestVPNConfirmationConfigurationIsImmutable(t *testing.T) {
	for _, initiallyEnabled := range []bool{true, false} {
		fixture, _ := confirmationController(t, "")
		configuration := fixture.config
		enabled := initiallyEnabled
		configuration.VPNLoginConfirmation = &enabled
		backend := &confirmationBackend{}
		control, err := New(configuration, fixture.origin, fixture.sp, backend, nil)
		if err != nil {
			t.Fatal(err)
		}
		enabled = !enabled
		response := httptest.NewRecorder()
		control.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, fixture.origin.String()+"/login/test-ticket", nil))
		wantStatus, wantStarts := http.StatusOK, 0
		if !initiallyEnabled {
			wantStatus, wantStarts = http.StatusFound, 1
		}
		if response.Code != wantStatus || backend.starts != wantStarts {
			t.Fatal("changing the caller's configuration changed a running controller")
		}
	}
}
