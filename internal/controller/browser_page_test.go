// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestBrowserPageStylePolicyAndSize(t *testing.T) {
	for _, kind := range []string{"welcome", "confirmation", "import", "verified", "error"} {
		t.Run(kind, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := confirmationController(t, "")
			policy, ok := c.confirmationCSP()
			if !ok {
				t.Fatal("fixture policy")
			}
			w.Header().Set("Content-Security-Policy", policy)
			renderBrowserPage(w, http.StatusOK, browserPageData{Kind: kind, Title: "Go Supi!", Message: "Test message", Action: "/login/test", Token: "synthetic", ImportAddress: "https://vpn.example.test/profile/import/synthetic", DownloadPath: "/profile"})
			body := w.Body.String()
			style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(body)
			if len(style) != 2 || len(body) > 10<<10 {
				t.Fatal("missing stylesheet or exceeded 10 KiB uncompressed page budget")
			}
			hash := sha256.Sum256([]byte(style[1]))
			csp := w.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "style-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") ||
				!strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
				!strings.Contains(csp, "base-uri 'none'") || strings.Contains(csp, "unsafe-inline") {
				t.Fatal("stylesheet does not match restrictive policy")
			}
			if kind == "confirmation" && !strings.HasPrefix(csp, policy+";") ||
				kind != "confirmation" && !strings.Contains(csp, "form-action 'none'") {
				t.Fatal("form destination policy changed")
			}
			for _, unwanted := range []string{"<script", "<link", "<img", "<iframe", "style=", "@import", "url("} {
				if strings.Contains(body, unwanted) {
					t.Fatal("unexpected active or external page resource")
				}
			}
			for header, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
				if w.Header().Get(header) != want {
					t.Fatal("missing browser protection", header)
				}
			}
			if kind == "import" && !strings.Contains(body, `href="openvpn://import-profile/https://vpn.example.test/profile/import/synthetic"`) {
				t.Fatal("custom-scheme handoff was altered")
			}
		})
	}
}

func TestBrowserPageEscapesTextAndAttributes(t *testing.T) {
	w := httptest.NewRecorder()
	renderBrowserPage(w, http.StatusOK, browserPageData{Kind: "confirmation",
		Title: `"><script>alert(1)</script>`, Message: `<img src=x onerror=alert(1)>`,
		Action: "javascript:alert(1)", Token: `" autofocus onfocus="alert(1)`})
	body := w.Body.String()
	if strings.Contains(body, "<script") || strings.Contains(body, "<img") ||
		strings.Contains(body, `value="" autofocus`) || strings.Contains(body, `action="javascript:`) {
		t.Fatal("page data escaped its HTML context")
	}
	// A missing confirmation policy must fail closed, not allow arbitrary forms.
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'none'") {
		t.Fatal("missing policy failed open")
	}
}

func TestBrowserMessagesPreserveStatusAndTextClients(t *testing.T) {
	for _, status := range []int{200, 202, 400, 403, 409, 410, 503} {
		for _, accept := range []string{"", "*/*", "application/json", "text/html;q=0", "text/html;q=0.0", "text/html;q=NaN", "text/html", "text/html;q=0.9,application/xhtml+xml"} {
			r := httptest.NewRequest("GET", "https://vpn.example.test/", nil)
			r.Header.Set("Accept", accept)
			w := httptest.NewRecorder()
			browserMessage(w, r, "Static operator guidance.", status)
			html := accept == "text/html" || strings.HasPrefix(accept, "text/html;q=0.9")
			if w.Code != status || strings.Contains(w.Header().Get("Content-Type"), "text/html") != html {
				t.Fatal("status or content negotiation changed", status, accept)
			}
			if !html && w.Body.String() != "Static operator guidance.\n" {
				t.Fatal("text response changed")
			}
			if html && status < 400 && !strings.Contains(w.Body.String(), "Your VPN client will confirm when the tunnel is connected.") {
				t.Fatal("browser claims a tunnel before client confirmation")
			}
		}
	}
}

func BenchmarkBrowserPage(b *testing.B) {
	page := browserPageData{Kind: "confirmation", Title: "Did you start this connection?", Message: "Continue only if you started this connection.", Action: "/login/synthetic", Token: "synthetic"}
	for b.Loop() {
		renderBrowserPage(httptest.NewRecorder(), http.StatusOK, page)
	}
}

func TestTransportRetryPageDoesNotClaimAuthorization(t *testing.T) {
	for _, accept := range []string{"text/html", "text/plain"} {
		r := httptest.NewRequest("GET", "https://vpn.example.test/", nil)
		r.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		browserMessage(w, r, connectionRetryMessage, http.StatusAccepted)
		body := w.Body.String()
		if w.Code != http.StatusAccepted || !strings.Contains(body, connectionRetryMessage) || strings.Contains(body, "still processing") || strings.Contains(body, "Sign-in verified.") {
			t.Fatal("retry page did not explain refusal and fresh sign-in")
		}
	}
}
