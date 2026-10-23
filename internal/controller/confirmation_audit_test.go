// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"supivpn/internal/saml"
)

type confirmationBackend struct {
	starts int
	hash   [32]byte
}

func (b *confirmationBackend) Ready(context.Context) bool { return true }
func (b *confirmationBackend) Start(_ context.Context, _, _ string, hash [32]byte) error {
	if b.starts != 0 {
		return ErrLoginStarted
	}
	b.starts++
	b.hash = hash
	return nil
}
func (*confirmationBackend) Lookup(context.Context, string, [32]byte) (Pending, error) {
	return Pending{}, ErrLoginExpired
}
func (*confirmationBackend) Complete(context.Context, Pending, Authorization) error {
	return ErrLoginExpired
}

func confirmationController(t *testing.T, prefix string) (*Controller, *confirmationBackend) {
	t.Helper()
	origin, err := url.Parse("https://vpn.example.test:8443" + prefix)
	if err != nil {
		t.Fatal(err)
	}
	sp := &saml.ServiceProvider{EntityID: origin.String() + "/saml/metadata",
		AcsURL: *origin.ResolveReference(&url.URL{Path: prefix + "/saml/acs"}),
		IDPMetadata: &saml.EntityDescriptor{EntityID: "https://idp.example.test", IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.test/login"}},
		}}}}
	backend := &confirmationBackend{}
	controller, err := New(Config{Policy: Policy{AllowedSubjects: []string{"alice"}}, PendingSeconds: 60, SessionSeconds: 3600}, origin, sp, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	return controller, backend
}

func TestVPNConfirmationRequiresBrowserAction(t *testing.T) {
	for _, prefix := range []string{"", "/supivpn"} {
		t.Run(prefix, func(t *testing.T) {
			controller, backend := confirmationController(t, prefix)
			handler := controller.Handler()
			entry := httptest.NewRequest(http.MethodGet, controller.origin.String()+"/login/test-ticket", nil)
			entry.Header.Set("Sec-Fetch-Site", "cross-site")
			entry.Header.Set("Referer", "https://untrusted.example.test/")
			page := httptest.NewRecorder()
			handler.ServeHTTP(page, entry)
			if page.Code != http.StatusOK || backend.starts != 0 || page.Header().Get("Location") != "" {
				t.Fatal("navigation started a VPN authorization flow")
			}
			if page.Header().Get("Referrer-Policy") != "same-origin" {
				t.Fatal("confirmation must preserve same-origin POST Origin without leaking a cross-origin Referer")
			}
			cookies := page.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing confirmation cookie")
			}
			cookie := cookies[0]
			if cookie.Name != ConfirmationCookieName("test-ticket") || !validConfirmationToken(cookie.Value) ||
				!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 60 {
				t.Fatal("confirmation cookie scope is unsafe")
			}
			for _, want := range []string{`method="post"`, `name="confirmation"`, `value="` + cookie.Value + `"`, "Do not continue from a link sent by someone else."} {
				if !strings.Contains(page.Body.String(), want) {
					t.Fatal("confirmation form or explanation missing")
				}
			}
			if strings.Contains(page.Body.String(), "<script") || !strings.Contains(page.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'; form-action 'self'") {
				t.Fatal("confirmation could be framed or auto-submitted")
			}
			body := url.Values{"confirmation": {cookie.Value}}.Encode()
			post := httptest.NewRequest(http.MethodPost, entry.URL.String(), strings.NewReader(body))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", "https://vpn.example.test:8443")
			post.AddCookie(cookie)
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, post)
			if result.Code != http.StatusFound || backend.starts != 1 || backend.hash == [32]byte{} {
				t.Fatal("explicit confirmation failed to start the bound SAML flow")
			}
			redirect, err := url.Parse(result.Header().Get("Location"))
			if err != nil || redirect.Host != "idp.example.test" || redirect.Query().Get("RelayState") != "test-ticket" {
				t.Fatal("confirmation changed the SAML destination or correlation")
			}
			cookies = result.Result().Cookies()
			if len(cookies) != 2 || cookies[0].Name != ConfirmationCookieName("test-ticket") || cookies[0].MaxAge != -1 || cookies[0].Value != "" ||
				cookies[1].Name != CookieName("test-ticket") || cookies[1].SameSite != http.SameSiteNoneMode || cookies[1].Value == cookie.Value {
				t.Fatal("SAML return cookie must be independent from confirmation")
			}
			originalHash := backend.hash
			replay := httptest.NewRequest(http.MethodPost, entry.URL.String(), strings.NewReader(body))
			replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			replay.Header.Set("Origin", "https://vpn.example.test:8443")
			replay.AddCookie(cookie)
			refused := httptest.NewRecorder()
			handler.ServeHTTP(refused, replay)
			if refused.Code != http.StatusConflict || backend.starts != 1 || backend.hash != originalHash || refused.Header().Get("Location") != "" {
				t.Fatal("replayed confirmation replaced the SAML browser binding")
			}
		})
	}
}

func TestVPNConfirmationRejectsCSRFAndAmbiguity(t *testing.T) {
	for _, attack := range []string{"missing-origin", "foreign-origin", "null-origin", "duplicate-origin", "origin-path", "missing-cookie", "duplicate-cookie", "wrong-cookie", "other-ticket", "duplicate-token", "extra-field", "wrong-type", "empty-token", "invalid-token", "body-limit", "query", "empty-query", "encoded-path"} {
		t.Run(attack, func(t *testing.T) {
			controller, backend := confirmationController(t, "")
			handler := controller.Handler()
			page := httptest.NewRecorder()
			handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, controller.origin.String()+"/login/test-ticket", nil))
			cookie := page.Result().Cookies()[0]
			body := url.Values{"confirmation": {cookie.Value}}.Encode()
			target := controller.origin.String() + "/login/test-ticket"
			switch attack {
			case "duplicate-token":
				body += "&confirmation=" + cookie.Value
			case "extra-field":
				body += "&other=x"
			case "empty-token":
				body = "confirmation="
			case "invalid-token":
				body = "confirmation=" + strings.Repeat("!", 43)
			case "body-limit":
				body += "&other=" + strings.Repeat("a", 4096)
			case "query":
				target += "?other=x"
			case "empty-query":
				target += "?"
			case "encoded-path":
				target = controller.origin.String() + "/login/%74est-ticket"
			}
			post := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			post.Header.Set("Origin", "https://vpn.example.test:8443")
			switch attack {
			case "missing-origin":
				post.Header.Del("Origin")
			case "foreign-origin":
				post.Header.Set("Origin", "https://untrusted.example.test")
			case "null-origin":
				post.Header.Set("Origin", "null")
			case "duplicate-origin":
				post.Header.Add("Origin", "https://vpn.example.test:8443")
			case "origin-path":
				post.Header.Set("Origin", "https://vpn.example.test:8443/supivpn")
			case "wrong-type":
				post.Header.Set("Content-Type", "text/plain")
			case "wrong-cookie":
				cookie.Value, _ = randomToken()
			case "other-ticket":
				cookie.Name = ConfirmationCookieName("other-ticket")
			}
			if attack != "missing-cookie" {
				post.AddCookie(cookie)
			}
			if attack == "duplicate-cookie" {
				post.AddCookie(cookie)
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, post)
			if result.Code < 400 || backend.starts != 0 || result.Header().Get("Location") != "" {
				t.Fatal("invalid confirmation started SAML")
			}
		})
	}
}

func TestVPNConfirmationPathAndDestinationBounds(t *testing.T) {
	for _, path := range []string{"/login/", "/login/profile_abc", "/login/" + strings.Repeat("a", 129), "/login/%74est-ticket", "/login/test%2fticket", "/login/test-ticket?x=1", "/login/test-ticket?"} {
		t.Run(path, func(t *testing.T) {
			controller, backend := confirmationController(t, "")
			response := httptest.NewRecorder()
			controller.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, controller.origin.String()+path, nil))
			if response.Code != http.StatusNotFound || backend.starts != 0 || len(response.Result().Cookies()) != 0 {
				t.Fatal("invalid ticket path reached confirmation")
			}
		})
	}
	for _, endpoint := range []string{"http://idp.example.test/login", "https://user@idp.example.test/login", "https://*.example.test/login", "https://idp.example.test;example.test/login", "https://idp.example.test/login#fragment", "https://idp.example.test\r\n/login"} {
		t.Run(endpoint, func(t *testing.T) {
			controller, backend := confirmationController(t, "")
			controller.sp.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location = endpoint
			response := httptest.NewRecorder()
			controller.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, controller.origin.String()+"/login/test-ticket", nil))
			if response.Code != http.StatusServiceUnavailable || backend.starts != 0 || len(response.Result().Cookies()) != 0 {
				t.Fatal("unsafe IdP destination entered the form policy")
			}
		})
	}
	controller, backend := confirmationController(t, "")
	response := httptest.NewRecorder()
	controller.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPut, controller.origin.String()+"/login/test-ticket", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, POST" || backend.starts != 0 {
		t.Fatal("unexpected confirmation method accepted")
	}
}

func TestVPNConfirmationBrowserOriginSerialization(t *testing.T) {
	for _, tc := range []struct{ configured, browser string }{
		{"https://VPN.Example.TEST", "https://vpn.example.test"},
		{"https://VPN.Example.TEST:443/supivpn", "https://vpn.example.test"},
		{"https://VPN.Example.TEST:0443", "https://vpn.example.test"},
		{"https://VPN.Example.TEST:08443", "https://vpn.example.test:8443"},
		{"https://[2001:DB8:0:0:0:0:0:1]:443", "https://[2001:db8::1]"},
		{"https://[2001:DB8::1]:8443/supivpn", "https://[2001:db8::1]:8443"},
		{"https://[::ffff:192.0.2.1]:443", "https://[::ffff:c000:201]"},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			controller, backend := confirmationController(t, "")
			origin, err := url.Parse(tc.configured)
			if err != nil {
				t.Fatal(err)
			}
			controller.sp.EntityID = origin.String() + "/saml/metadata"
			controller.sp.AcsURL = *origin.JoinPath("saml/acs")
			controller, err = New(controller.config, origin, controller.sp, backend, nil)
			if err != nil {
				t.Fatal("supported configured origin refused")
			}
			if got := serializedHTTPSOrigin(origin); got != tc.browser {
				t.Fatalf("configured origin serializes as %q, want %q", got, tc.browser)
			}
			handler := controller.Handler()
			target := origin.String() + "/login/test-ticket"
			page := httptest.NewRecorder()
			handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, target, nil))
			if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
				t.Fatal("confirmation unavailable")
			}
			cookie := page.Result().Cookies()[0]
			body := url.Values{"confirmation": {cookie.Value}}.Encode()
			send := func(value string) int {
				post := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
				post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				post.Header.Set("Origin", value)
				post.AddCookie(cookie)
				result := httptest.NewRecorder()
				handler.ServeHTTP(result, post)
				return result.Code
			}
			for _, bad := range []string{tc.browser + "/", tc.browser + "/supivpn", tc.browser + " https://untrusted.example.test", "https://untrusted.example.test"} {
				if send(bad) != http.StatusForbidden || backend.starts != 0 {
					t.Fatal("non-exact browser Origin accepted")
				}
			}
			if send(tc.browser) != http.StatusFound || backend.starts != 1 {
				t.Fatal("browser-serialized Origin refused")
			}
		})
	}
}

func TestControllerHTTPSAuthorityEquivalence(t *testing.T) {
	for _, host := range []string{"vpn.example.test", "VPN.EXAMPLE.TEST", "vpn.example.test:443", "vpn.example.test:0443"} {
		controller, backend := confirmationController(t, "")
		origin, _ := url.Parse("https://VPN.Example.TEST:443")
		controller.sp.EntityID = origin.String() + "/saml/metadata"
		controller.sp.AcsURL = *origin.JoinPath("saml/acs")
		var err error
		controller, err = New(controller.config, origin, controller.sp, backend, nil)
		if err != nil {
			t.Fatal(err)
		}
		handler := controller.Handler()
		for _, tc := range []struct {
			name, host string
			plaintext  bool
			want       int
		}{
			{"equivalent", host, false, http.StatusOK},
			{"alternate-port", "vpn.example.test:8443", false, http.StatusBadRequest},
			{"foreign-host", "untrusted.example.test", false, http.StatusBadRequest},
			{"userinfo", "user@vpn.example.test", false, http.StatusBadRequest},
			{"suffix", "vpn.example.test.untrusted.example.test", false, http.StatusBadRequest},
			{"path", "vpn.example.test/path", false, http.StatusBadRequest},
			{"query", "vpn.example.test?x=1", false, http.StatusBadRequest},
			{"fragment", "vpn.example.test#fragment", false, http.StatusBadRequest},
			{"empty-port", "vpn.example.test:", false, http.StatusBadRequest},
			{"invalid-port", "vpn.example.test:65536", false, http.StatusBadRequest},
			{"plaintext", host, true, http.StatusBadRequest},
		} {
			t.Run(host+"/"+tc.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, origin.String()+"/healthz", nil)
				request.Host = tc.host
				if tc.plaintext {
					request.TLS = nil
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != tc.want {
					t.Fatalf("authority accepted with status %d, want %d", response.Code, tc.want)
				}
			})
		}
	}
}
