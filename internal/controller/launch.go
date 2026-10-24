// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"errors"
	"io"
	"net/http"
)

// launchProfile treats an IdP tile POST only as navigation. Its assertion and
// RelayState never establish an identity, select a destination, or access keys.
// A fresh browser-bound SP-initiated login begins at the fixed profile URL.
func (a *Controller) launchProfile(w http.ResponseWriter, r *http.Request) {
	if a.downloads == nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.EscapedPath() != a.origin.Path+"/saml/launch" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		browserMessage(w, r, "Launch query not allowed", http.StatusBadRequest)
		return
	}
	// Discard, rather than parse or log, even well-formed signed SAML. Bound
	// chunked bodies too; Content-Length alone is not a reliable size limit.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			browserMessage(w, r, "Launch body too large", http.StatusRequestEntityTooLarge)
		} else {
			browserMessage(w, r, "Invalid launch request", http.StatusBadRequest)
		}
		return
	}
	w.Header().Set("Location", a.origin.Path+"/profile")
	w.WriteHeader(http.StatusSeeOther)
}
