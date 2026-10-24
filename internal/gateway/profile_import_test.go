// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestProfileImportExactRoutes(t *testing.T) {
	origin, _ := url.Parse("https://vpn.example.test")
	calls := 0
	a, err := NewPublic(configForTest(), origin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Ovpn-WebAuth", "SupiVPN,external")
		w.WriteHeader(200)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, route string
		ok                  bool
	}{
		{"HEAD", "/openvpn-api/profile", "HEAD /openvpn-api/profile", true},
		{"GET", "/openvpn-api/profile", "GET /openvpn-api/profile", true},
		{"GET", "/profile/connect", "GET /profile/connect", true},
		{"GET", "/profile/import/" + strings.Repeat("a", 43), "GET /profile/import/{token}", true},
		{"GET", "/profile/import/" + strings.Repeat("a", 43), "ANY /{proxy+}", false},
		{"POST", "/profile/import/" + strings.Repeat("a", 43), "POST /profile/import/{token}", false},
		{"GET", "/profile/import/short", "GET /profile/import/{token}", false},
	} {
		e := eventFor(tc.method, tc.path)
		e.RouteKey = tc.route
		e.RequestContext.RouteKey = tc.route
		before := calls
		out, err := a.Handle(context.Background(), e)
		if err != nil || (out.StatusCode == 200) != tc.ok || (calls == before+1) != tc.ok {
			t.Fatal("incorrect import route dispatch")
		}
	}
}
