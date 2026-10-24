// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"supivpn/internal/saml"
)

// ConfirmationCookieName is separate from the cookie used for the SAML return.
// The host prefix prevents sibling domains from injecting a chosen token.
func ConfirmationCookieName(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return fmt.Sprintf("__Host-supivpn-confirm-%x", sum[:12])
}

func validLoginTicket(ticket string) bool {
	if ticket == "" || len(ticket) > 128 || strings.HasPrefix(ticket, "profile_") {
		return false
	}
	for _, ch := range ticket {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func validConfirmationToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(data) == 32
}

// Browsers serialize an HTTPS origin with a lowercase host and without the
// default port. For CSRF, normalize only the trusted configured origin: the
// incoming Origin header must still be one exact value, with no path or list.
func serializedHTTPSOrigin(origin *url.URL) string {
	if origin == nil || origin.Scheme != "https" || strings.HasSuffix(origin.Host, ":") {
		return ""
	}
	authority, err := url.Parse("https://" + origin.Host)
	if err != nil || authority.Host != origin.Host || authority.User != nil || authority.Path != "" ||
		authority.RawQuery != "" || authority.ForceQuery || authority.Fragment != "" {
		return ""
	}
	host := strings.ToLower(origin.Hostname())
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Zone() != "" {
			return ""
		}
		host = address.String()
		if address.Is4In6() {
			bytes := address.As16()
			host = fmt.Sprintf("::ffff:%x:%x", uint16(bytes[12])<<8|uint16(bytes[13]), uint16(bytes[14])<<8|uint16(bytes[15]))
		}
	}
	port := origin.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return ""
		}
		port = strconv.FormatUint(n, 10)
		if port == "443" {
			port = ""
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host
}

func (a *Controller) confirmationCSP() (string, bool) {
	endpoint, err := url.Parse(a.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return "", false
	}
	idpOrigin := endpoint.Scheme + "://" + endpoint.Host
	for _, ch := range idpOrigin {
		if ch <= ' ' || ch > '~' || strings.ContainsRune("\"';\\*", ch) {
			return "", false
		}
	}
	// Some browsers also check a form POST's redirect destination. Permit only
	// this trusted IdP origin, never arbitrary HTTPS sites or posted URLs.
	return "default-src 'none'; frame-ancestors 'none'; form-action 'self' " + idpOrigin + "; base-uri 'none'", true
}

// A copied pending-login URL does not prove that its browser owns the VPN
// client. By default, require a visible, same-origin action before SAML starts.
// Operators may explicitly disable this intent confirmation; it is not device binding.
func (a *Controller) login(w http.ResponseWriter, r *http.Request) {
	ticket := strings.TrimPrefix(r.URL.Path, a.origin.Path+"/login/")
	if !validLoginTicket(ticket) || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.EscapedPath() != a.origin.Path+"/login/"+ticket {
		http.NotFound(w, r)
		return
	}
	csp, ok := a.confirmationCSP()
	if !ok {
		browserMessage(w, r, "Cannot start SSO", http.StatusServiceUnavailable)
		return
	}
	if enabled := a.config.VPNLoginConfirmation; enabled != nil && !*enabled {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		a.startLogin(w, r, ticket, a.backend)
		return
	}
	w.Header().Set("Content-Security-Policy", csp)
	// Preserve the browser's Origin on this same-origin form submission while
	// withholding the ticket-bearing Referer from the cross-origin IdP.
	w.Header().Set("Referrer-Policy", "same-origin")
	name := ConfirmationCookieName(ticket)
	switch r.Method {
	case http.MethodGet:
		token, err := randomToken()
		if err != nil {
			browserMessage(w, r, "Cannot start SSO", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: "/", HttpOnly: true,
			Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: a.config.PendingSeconds})
		renderBrowserPage(w, http.StatusOK, browserPageData{
			Kind: "confirmation", Title: "Did you start this connection?", Eyebrow: "Confirm VPN sign-in",
			Message: "Continue only if you just started connecting in your VPN client. Your organization will verify your identity next.",
			Notice:  "This page authorizes the connection that requested it. Do not continue from a link sent by someone else.",
			Action:  r.URL.Path, Token: token,
		})
	case http.MethodPost:
		origins := r.Header.Values("Origin")
		expectedOrigin := serializedHTTPSOrigin(a.origin)
		if expectedOrigin == "" || len(origins) != 1 || origins[0] != expectedOrigin {
			browserMessage(w, r, "VPN sign-in confirmation refused", http.StatusForbidden)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" {
			browserMessage(w, r, "Invalid VPN sign-in confirmation", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ParseForm() != nil || len(r.PostForm) != 1 || len(r.PostForm["confirmation"]) != 1 {
			browserMessage(w, r, "Invalid VPN sign-in confirmation", http.StatusBadRequest)
			return
		}
		token := r.PostForm.Get("confirmation")
		var cookieValue string
		count := 0
		for _, cookie := range r.Cookies() {
			if cookie.Name == name {
				count++
				cookieValue = cookie.Value
			}
		}
		if count != 1 || !validConfirmationToken(token) || !validConfirmationToken(cookieValue) ||
			subtle.ConstantTimeCompare([]byte(token), []byte(cookieValue)) != 1 {
			browserMessage(w, r, "VPN sign-in confirmation refused", http.StatusForbidden)
			return
		}
		// Start atomically consumes the pending connection's unstarted state.
		// Replaying this form cannot replace the resulting SAML browser binding.
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteStrictMode, MaxAge: -1})
		a.startLogin(w, r, ticket, a.backend)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
