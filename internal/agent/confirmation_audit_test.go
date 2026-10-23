// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"supivpn/internal/controller"
)

// Follow the visible confirmation page before SAML in transport fixtures. Do
// not initialize browser/request state directly: the real controller must do it.
func confirmVPNLogin(t *testing.T, handler http.Handler, origin *url.URL, ticket string) *httptest.ResponseRecorder {
	t.Helper()
	target := origin.String() + "/login/" + ticket
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, target, nil))
	if page.Code != http.StatusOK || page.Header().Get("Location") != "" || len(page.Result().Cookies()) != 1 {
		t.Fatal("VPN confirmation page unavailable")
	}
	cookie := page.Result().Cookies()[0]
	if cookie.Name != controller.ConfirmationCookieName(ticket) || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode ||
		!strings.Contains(page.Body.String(), `name="confirmation" value="`+cookie.Value+`"`) {
		t.Fatal("VPN confirmation form or cookie unavailable")
	}
	body := url.Values{"confirmation": {cookie.Value}}.Encode()
	post := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", origin.Scheme+"://"+origin.Host)
	post.AddCookie(cookie)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, post)
	return result
}

func samlLoginCookie(t *testing.T, response *http.Response, ticket string) *http.Cookie {
	t.Helper()
	var samlCookie *http.Cookie
	cleared := false
	for _, cookie := range response.Cookies() {
		switch cookie.Name {
		case controller.CookieName(ticket):
			if samlCookie != nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Value == "" {
				t.Fatal("invalid SAML browser cookie")
			}
			samlCookie = cookie
		case controller.ConfirmationCookieName(ticket):
			if cleared || cookie.MaxAge != -1 || cookie.Value != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("confirmation cookie was not cleared")
			}
			cleared = true
		default:
			t.Fatal("unexpected login cookie")
		}
	}
	if samlCookie == nil || !cleared {
		t.Fatal("login cookie transition incomplete")
	}
	return samlCookie
}

func TestVPNNavigationDoesNotBindOrAuthorizeConnection(t *testing.T) {
	_, metadata := testIdP(t)
	app, commands := testApp(t, metadata)
	app.tickets["test-ticket"].requestID = ""
	app.tickets["test-ticket"].browserHash = [32]byte{}
	request := httptest.NewRequest(http.MethodGet, app.origin.String()+"/login/test-ticket", nil)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Referer", "https://untrusted.example.test/")
	page := httptest.NewRecorder()
	app.handler().ServeHTTP(page, request)
	if page.Code != http.StatusOK || page.Header().Get("Location") != "" || app.tickets["test-ticket"].requestID != "" ||
		app.tickets["test-ticket"].browserHash != [32]byte{} || app.connections[7].active || len(commands) != 0 {
		t.Fatal("mere navigation started SSO or authorized a connection")
	}
	confirmed := confirmVPNLogin(t, app.handler(), app.origin, "test-ticket")
	if confirmed.Code != http.StatusFound || app.tickets["test-ticket"].requestID == "" || app.connections[7].active || len(commands) != 0 {
		t.Fatal("confirmation must start SAML without authorizing the tunnel")
	}
}
