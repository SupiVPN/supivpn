// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

// Synthetic deterministic credentials let retry tests reuse exactly one proof.
// This helper belongs only to the disposable database tests, never production.
func ownedFixtureProof(t *testing.T, s *postgres.Store, owner [32]byte, label string) profile.Credential {
	t.Helper()
	id := sha256.Sum256([]byte("test-profile-id:" + label))
	secret := sha256.Sum256([]byte("test-profile-secret:" + label))
	p := profile.Credential{ID: "svp1_" + hex.EncodeToString(id[:16]), Secret: base64.RawURLEncoding.EncodeToString(secret[:])}
	if _, err := s.ProfileState(context.Background(), p.ID); err != nil {
		if err := s.CreateProfile(context.Background(), p, profile.Owner{SubjectHash: owner}); err != nil {
			t.Fatal("create synthetic owned profile", err)
		}
	}
	return p
}

func registerOwnedFixture(t *testing.T, s *postgres.Store, ctx context.Context, a postgres.Agent, c postgres.Connection, ticket string, ttl time.Duration, owner [32]byte) error {
	t.Helper()
	p := ownedFixtureProof(t, s, owner, t.Name()+":"+a.NodeID+":"+ticket)
	return s.RegisterProfile(ctx, a, c, ticket, ttl, p)
}

// Reconstruct a grant written by an old release. Current admission deliberately
// cannot create this unbound state; migration tests must not bypass that rule in
// product code merely to manufacture their historical input.
func seedHistoricalGrant(t *testing.T, p *pgxpool.Pool, a postgres.Agent, c postgres.Connection, ticket string, subject [32]byte, label string, schema int) {
	t.Helper()
	hash := sha256.Sum256([]byte(ticket))
	browser := sha256.Sum256([]byte("synthetic-browser:" + ticket))
	_, err := p.Exec(context.Background(), `INSERT INTO supivpn.logins
	(ticket_hash,node_id,generation,cid,kid,expires_at,request_id,browser_hash,state,decision_id,group_name,subject_hash,not_before,not_after,session_expires_at)
	VALUES($1,$2,$3,$4,$5,now()+interval '1 minute',$6,$7,'decided',$8,'admins-vpn',$9,now()-interval '1 minute',now()+interval '1 minute',now()+interval '1 hour')`,
		hash[:], a.NodeID, a.Generation, c.CID, c.KID, "request-"+ticket, browser[:], "decision-"+ticket, subject[:])
	if err != nil {
		t.Fatal("historical grant fixture", err)
	}
	if schema >= 8 {
		if _, err = p.Exec(context.Background(), "UPDATE supivpn.logins SET username=$2 WHERE ticket_hash=$1", hash[:], label); err != nil {
			t.Fatal("historical label fixture", err)
		}
	}
	if _, err = p.Exec(context.Background(), "INSERT INTO supivpn.assertions(assertion_hash,expires_at) VALUES($1,now()+interval '1 minute')", hash[:]); err != nil {
		t.Fatal("historical replay fixture", err)
	}
}

func historicalGrantSnapshot(t *testing.T, p *pgxpool.Pool, ticket string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(ticket))
	var snapshot string
	if err := p.QueryRow(context.Background(), "SELECT (to_jsonb(l)-'username')::text FROM supivpn.logins l WHERE ticket_hash=$1", hash[:]).Scan(&snapshot); err != nil {
		t.Fatal("historical grant snapshot", err)
	}
	return snapshot
}
