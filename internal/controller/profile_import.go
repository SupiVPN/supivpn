// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strings"
	"supivpn/internal/logging"
)

// ProfileImports stores only one-use handoffs across controller replicas.
type ProfileImports interface {
	CreateImport(context.Context, string, [32]byte) error
	ConsumeImport(context.Context, string) ([32]byte, error)
}

func (a *Controller) discoverProfile(w http.ResponseWriter, r *http.Request) {
	if a.downloads == nil || a.downloads.Imports == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Ovpn-WebAuth", "SupiVPN,external")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	// Client-supplied device metadata and redirect URLs are deliberately ignored.
	fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Go Supi!</title><h1>Go Supi!</h1><p>Sign in with your organization to import your VPN profile.</p><a href="%s">Continue to sign in</a></html>`, html.EscapeString(a.origin.Path+"/profile/connect"))
}

func (a *Controller) connectProfile(w http.ResponseWriter, r *http.Request) {
	if a.downloads == nil || a.downloads.Imports == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ticket, err := randomToken()
	if err != nil {
		http.Error(w, "Cannot start SSO", 500)
		return
	}
	a.startLogin(w, r, "profile_url_"+ticket, a.downloads.Backend)
}

func (a *Controller) handoffProfile(w http.ResponseWriter, r *http.Request, subject [32]byte) {
	if a.downloads.Imports == nil {
		http.Error(w, "Import unavailable", 503)
		return
	}
	token, err := randomToken()
	if err != nil || a.downloads.Imports.CreateImport(r.Context(), token, subject) != nil {
		http.Error(w, "Import unavailable. Sign in again.", 503)
		return
	}
	address := a.origin.String() + "/profile/import/" + token
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// An explicit gesture avoids silently opening a local application. No script,
	// third-party asset or redirect target can observe the bearer handoff.
	fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Go Supi!</title><h1>Your tunnel is ready to import.</h1><p>This link works once and expires in 60 seconds. Keep it private.</p><a href="%s">Open in OpenVPN Connect</a><p>Linux: use the <a href="%s">profile download</a> instead.</p></html>`, html.EscapeString("openvpn://import-profile/"+address), html.EscapeString(a.origin.Path+"/profile"))
}

func (a *Controller) importProfile(w http.ResponseWriter, r *http.Request) {
	if a.downloads == nil || a.downloads.Imports == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, a.origin.Path+"/profile/import/")
	subject, err := a.downloads.Imports.ConsumeImport(r.Context(), token)
	if err != nil {
		http.Error(w, "Import expired or already used. Sign in again.", http.StatusGone)
		return
	}
	a.issueProfile(w, r, subject)
}

func (a *Controller) issueProfile(w http.ResponseWriter, r *http.Request, subject [32]byte) {
	var data []byte
	var err error
	if a.downloads.IssueForSubject != nil {
		data, err = a.downloads.IssueForSubject(r.Context(), subject)
	} else {
		data, err = a.downloads.Issue(r.Context())
	}
	defer clear(data)
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		logging.Emit(r.Context(), "profile.issue_failed")
		http.Error(w, "Profile unavailable. Open the profile link to sign in again.", 503)
		return
	}
	logging.Emit(r.Context(), "profile.issued")
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", `attachment; filename="supivpn.ovpn"`)
	w.Header().Set("Cache-Control", "no-store, private")
	w.Write(data)
}
