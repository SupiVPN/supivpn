// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"testing"
	"time"
)

type proofStore struct {
	recordedStore
	proof profile.Credential
}

func (s *proofStore) RegisterProfile(ctx context.Context, a postgres.Agent, c postgres.Connection, ticket string, ttl time.Duration, p profile.Credential) error {
	s.proof = p
	return s.Register(ctx, a, c, ticket, ttl)
}
func TestProfileProofAPI(t *testing.T) {
	c, _ := profile.NewCredential()
	fields := map[string]any{"generation": "g1", "cid": 7, "kid": 2, "ticket": strings.Repeat("x", 43), "profile_id": c.ID, "profile_secret": c.Secret}
	body, _ := json.Marshal(fields)
	s := &proofStore{}
	w := httptest.NewRecorder()
	New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/register", string(body), "trusted-node"))
	if w.Code != 204 || s.proof != c || s.actor.NodeID != "trusted-node" || s.conn.CID != 7 || s.conn.KID != 2 {
		t.Fatal("proof detached from authenticated connection")
	}
	old := &recordedStore{}
	w = httptest.NewRecorder()
	New(old, time.Minute).ServeHTTP(w, requestFor("/agent/v1/register", string(body), "trusted-node"))
	if w.Code != 503 || old.calls != 0 {
		t.Fatal("unsupported proof silently fell back")
	}
	for _, field := range []string{"profile_id", "profile_secret"} {
		bad := map[string]any{}
		for k, v := range fields {
			bad[k] = v
		}
		delete(bad, field)
		b, _ := json.Marshal(bad)
		s = &proofStore{}
		w = httptest.NewRecorder()
		New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/register", string(b), "trusted-node"))
		if w.Code != 400 || s.calls != 0 {
			t.Fatal("partial proof accepted")
		}
	}
}

func TestUnboundRegisterCannotUseLegacyStore(t *testing.T) {
	for _, s := range []Store{&recordedStore{}, &proofStore{}} {
		w := httptest.NewRecorder()
		body := `{"generation":"g1","cid":7,"kid":2,"ticket":"` + strings.Repeat("x", 43) + `"}`
		New(s, time.Minute).ServeHTTP(w, requestFor("/agent/v1/register", body, "trusted-node"))
		if w.Code != 400 {
			t.Fatal("missing proof accepted by authenticated API")
		}
	}
}
