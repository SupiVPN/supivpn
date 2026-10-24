// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package controller implements the browser/SAML control plane without an
// OpenVPN socket, IP allocator, AWS SDK, listener, or process lifecycle.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"supivpn/internal/logging"
	"time"

	"supivpn/internal/saml"
	"supivpn/internal/tracecontext"
)

type Config struct {
	Policy
	PendingSeconds       int
	SessionSeconds       int
	VPNLoginConfirmation *bool
}

type Controller struct {
	config    Config
	origin    *url.URL
	sp        *saml.ServiceProvider
	backend   Backend
	allowed   map[string]bool
	now       func() time.Time
	downloads *ProfileDownloads
}

// ProfileDownloads uses separate pending state; it never authorizes an agent
// connection or embeds a SAML login/session credential in a client profile.
type ProfileDownloads struct {
	Backend         Backend
	Imports         ProfileImports
	Issue           func(context.Context) ([]byte, error)
	IssueForSubject func(context.Context, [32]byte) ([]byte, error)
}

func New(c Config, origin *url.URL, sp *saml.ServiceProvider, backend Backend, now func() time.Time, downloads ...ProfileDownloads) (*Controller, error) {
	if origin == nil || origin.Scheme != "https" || origin.Host == "" ||
		origin.User != nil || (origin.Path != "" && origin.Path != "/supivpn") || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		sp == nil || sp.AllowIDPInitiated || backend == nil ||
		sp.EntityID != origin.String()+"/saml/metadata" ||
		sp.AcsURL.String() != origin.String()+"/saml/acs" {
		return nil, errors.New("invalid controller origin, service provider or backend")
	}
	if c.PendingSeconds < 30 || c.PendingSeconds > 180 || !ValidSessionSeconds(c.SessionSeconds) {
		return nil, errors.New("invalid authentication time limits")
	}
	if err := ValidatePolicy(c.Policy); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if c.VPNLoginConfirmation != nil {
		enabled := *c.VPNLoginConfirmation
		c.VPNLoginConfirmation = &enabled
	}
	c.AllowedSubjects = append([]string(nil), c.AllowedSubjects...)
	c.Groups = append([]Group(nil), c.Groups...)
	for i := range c.Groups {
		if value := c.Groups[i].SessionSeconds; value != nil {
			seconds := *value
			c.Groups[i].SessionSeconds = &seconds
		}
	}
	if c.HasUnlimitedSessions() {
		logging.Emit(context.Background(), "session.unlimited_configured")
	}
	u := *origin
	a := &Controller{config: c, origin: &u, sp: sp, backend: backend, now: now, allowed: make(map[string]bool)}
	if len(downloads) > 1 {
		return nil, errors.New("invalid profile download configuration")
	}
	if len(downloads) == 1 {
		d := downloads[0]
		if d.Backend == nil || (d.Issue == nil) == (d.IssueForSubject == nil) || c.SAMLGroupsAttribute == "" {
			return nil, errors.New("profile downloads require a backend, issuer and group authorization")
		}
		a.downloads = &d
	}
	for _, subject := range c.AllowedSubjects {
		a.allowed[subject] = true
	}
	return a, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(a.origin.Path+"/healthz", a.health)
	mux.HandleFunc(a.origin.Path+"/saml/metadata", a.metadata)
	mux.HandleFunc(a.origin.Path+"/login/", a.login)
	mux.HandleFunc(a.origin.Path+"/saml/acs", a.acs)
	mux.HandleFunc(a.origin.Path+"/saml/launch", a.launchProfile)
	mux.HandleFunc(a.origin.Path+"/profile", a.profile)
	mux.HandleFunc(a.origin.Path+"/openvpn-api/profile", a.discoverProfile)
	mux.HandleFunc(a.origin.Path+"/profile/connect", a.connectProfile)
	mux.HandleFunc(a.origin.Path+"/profile/import/", a.importProfile)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(tracecontext.New(r.Context()))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		expectedOrigin := serializedHTTPSOrigin(a.origin)
		if r.TLS == nil || expectedOrigin == "" || serializedHTTPSOrigin(&url.URL{Scheme: "https", Host: r.Host}) != expectedOrigin {
			http.Error(w, "Invalid HTTPS origin", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *Controller) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !a.backend.Ready(r.Context()) {
		http.Error(w, "Authorization backend unavailable", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ready")
}

func (a *Controller) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	md := a.sp.Metadata()
	// Only the implemented HTTP-POST ACS binding is advertised.
	for i := range md.SPSSODescriptors {
		md.SPSSODescriptors[i].AssertionConsumerServices = []saml.IndexedEndpoint{
			{Binding: saml.HTTPPostBinding, Location: a.sp.AcsURL.String(), Index: 1},
		}
	}
	b, err := xml.Marshal(md)
	if err != nil {
		http.Error(w, "Metadata unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}

func CookieName(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return fmt.Sprintf("__Host-supivpn-%x", sum[:12])
}

func (a *Controller) profile(w http.ResponseWriter, r *http.Request) {
	if a.downloads == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ticket, err := randomToken()
	if err != nil {
		http.Error(w, "Cannot start SSO", http.StatusInternalServerError)
		return
	}
	a.startLogin(w, r, "profile_"+ticket, a.downloads.Backend)
}

func (a *Controller) startLogin(w http.ResponseWriter, r *http.Request, ticket string, backend Backend) {
	req, err := a.sp.MakeAuthenticationRequest(a.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		http.Error(w, "Cannot start SSO", http.StatusInternalServerError)
		return
	}
	destination, err := req.Redirect(ticket, a.sp)
	if err != nil {
		http.Error(w, "Cannot start SSO", http.StatusInternalServerError)
		return
	}
	browser, err := randomToken()
	if err != nil {
		http.Error(w, "Cannot start SSO", http.StatusInternalServerError)
		return
	}
	if err := backend.Start(r.Context(), ticket, req.ID, sha256.Sum256([]byte(browser))); err != nil {
		switch {
		case errors.Is(err, ErrLoginStarted):
			browserError(w, r, "Login already started. Reconnect to start again.", http.StatusConflict)
		case errors.Is(err, ErrLoginExpired):
			browserError(w, r, "Login expired. Reconnect in OpenVPN Connect.", http.StatusGone)
		default:
			browserError(w, r, "VPN unavailable. Reconnect.", http.StatusServiceUnavailable)
		}
		return
	}
	r = r.WithContext(tracecontext.WithID(r.Context(), tracecontext.ForLogin(ticket)))
	logging.Emit(r.Context(), "saml.login_started", slog.String("purpose", loginPurpose(ticket)))
	http.SetCookie(w, &http.Cookie{Name: CookieName(ticket), Value: browser,
		Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
		MaxAge: a.config.PendingSeconds})
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (a *Controller) acs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil ||
		len(r.PostForm["RelayState"]) != 1 || len(r.PostForm["SAMLResponse"]) != 1 {
		browserError(w, r, "Invalid SAML response", http.StatusBadRequest)
		return
	}
	ticket := r.PostForm.Get("RelayState")
	backend := a.backend
	isProfile := strings.HasPrefix(ticket, "profile_")
	if isProfile {
		if a.downloads == nil {
			http.Error(w, "Profile login unavailable", http.StatusGone)
			return
		}
		backend = a.downloads.Backend
	}
	cookie, err := r.Cookie(CookieName(ticket))
	if err != nil || cookie.Value == "" {
		browserError(w, r, "Login browser mismatch", http.StatusForbidden)
		return
	}
	pending, err := backend.Lookup(r.Context(), ticket, sha256.Sum256([]byte(cookie.Value)))
	if err != nil {
		if errors.Is(err, ErrLoginExpired) {
			browserError(w, r, "Login expired", http.StatusGone)
		} else {
			browserError(w, r, "VPN unavailable. Reconnect.", http.StatusServiceUnavailable)
		}
		return
	}
	// Only the bounded, signature-validated assertion is used for authorization.
	r = r.WithContext(tracecontext.WithID(r.Context(), tracecontext.ForLogin(pending.Ticket)))
	assertion, err := parseSAMLResponse(a.sp, r.PostForm.Get("SAMLResponse"), pending.RequestID)
	if err != nil || !a.acceptableAssertion(assertion, pending.RequestID) {
		// Library errors can embed the complete assertion. Do not log them.
		logging.Emit(r.Context(), "saml.response_refused")
		http.Error(w, "SSO refused. Check application assignment and test user.", http.StatusForbidden)
		return
	}
	var groupName, denialReason string
	if a.config.SAMLGroupsAttribute != "" {
		memberships, groupErr := assertionGroups(assertion, a.config.SAMLGroupsAttribute)
		var selected Group
		if groupErr == nil {
			selected, groupErr = selectGroup(a.config.Groups, memberships)
		}
		if groupErr != nil {
			denialReason = "invalid_groups_claim"
			if errors.Is(groupErr, ErrNoGroup) {
				denialReason = "no_vpn_group"
			}
		} else {
			groupName = selected.GroupName
		}
	}
	decision := a.authorizationBounds(assertion, pending.RequestID, groupName)
	decision.DenialReason = denialReason
	decision.MaxConnections = a.config.ConnectionLimit(groupName)
	err = backend.Complete(r.Context(), pending, decision)
	awaitingAgent := errors.Is(err, ErrDecisionPending)
	if err != nil && !awaitingAgent {
		switch {
		case errors.Is(err, ErrLoginExpired):
			http.Error(w, "Login already used or expired", http.StatusGone)
		case errors.Is(err, ErrGroupDenied):
			logging.Emit(r.Context(), "saml.authorization_decided", slog.String("purpose", loginPurpose(ticket)), slog.String("outcome", "denied"), slog.String("reason", denialReason))
			http.Error(w, "VPN group authorization refused. Contact your administrator.", http.StatusForbidden)
		case errors.Is(err, ErrConnectionLimit):
			logging.Emit(r.Context(), "saml.authorization_decided", slog.String("purpose", loginPurpose(ticket)), slog.String("outcome", "denied"), slog.String("reason", "connection_limit"))
			http.Error(w, "VPN connection limit reached. If you just cancelled or disconnected, wait for the previous connection to close, then reconnect. Otherwise, disconnect another VPN session and try again.", http.StatusForbidden)
		default:
			http.Error(w, "VPN unavailable. Reconnect.", http.StatusServiceUnavailable)
		}
		return
	}
	logging.Emit(r.Context(), "saml.authorization_decided", slog.String("purpose", loginPurpose(ticket)), slog.String("outcome", "allowed"))
	http.SetCookie(w, &http.Cookie{Name: cookie.Name, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	if awaitingAgent {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "Sign-in verified. Waiting for the VPN server; check OpenVPN Connect.")
		return
	}
	if isProfile {
		if strings.HasPrefix(ticket, "profile_url_") {
			a.handoffProfile(w, r, decision.SubjectHash)
		} else {
			a.issueProfile(w, r, decision.SubjectHash)
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Sign-in accepted. Return to OpenVPN Connect to check the connection.")
}

func loginPurpose(ticket string) string {
	if strings.HasPrefix(ticket, "profile_") {
		return "profile_download"
	}
	return "vpn_connect"
}

// Before browser/backend binding is verified, retain the independent request
// trace. An attacker-provided ticket/header must not attach a failure to a VPN.
func browserError(w http.ResponseWriter, r *http.Request, message string, status int) {
	logging.Emit(r.Context(), "saml.request_refused", slog.Int("status", status))
	http.Error(w, message, status)
}
