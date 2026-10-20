// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestSecurityIsolatedSurfaces(t *testing.T) {
	origin, _ := url.Parse("https://vpn.example.test")
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })
	public, err := NewPublic(configForTest(), origin, h)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(configForTest(), origin, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []*Adapter{public, agent} {
		calls = 0
		p, _ := a.Handle(context.Background(), eventFor("GET", "/healthz"))
		n, _ := a.Handle(context.Background(), iamEvent())
		if calls != 1 || a == public && (p.StatusCode != 204 || n.StatusCode != 403) || a == agent && (p.StatusCode != 403 || n.StatusCode != 204) {
			t.Fatal("cross-component route accepted")
		}
	}
}
