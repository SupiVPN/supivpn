// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

func TestProfileOwnerMigrationPreservesExistingCredentials(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.nodes,supivpn.assertions,supivpn.issued_profiles CASCADE"); err != nil {
		t.Fatal("reset")
	}
	removeProfileOwnerSchema(t, pool)
	t.Cleanup(func() {
		if err := postgres.Migrate(ctx, pool); err != nil {
			t.Error("restore schema", err)
		}
	})
	s := postgres.New(pool)
	actor := postgres.Agent{NodeID: "owner-migration", Generation: "g1"}
	if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
		t.Fatal(err)
	}
	labels := []string{"alice@example.test", "", "", "blocked-owner@example.test", ""}
	credentials := make([]profile.Credential, len(labels))
	subjects := make([][32]byte, len(labels))
	for i := range labels {
		credentials[i], _ = profile.NewCredential()
		subjects[i] = sha256.Sum256([]byte(fmt.Sprintf("verified-owner-%d", i)))
		digest, _ := credentials[i].Digest()
		state, revision := "active", int64(1)
		if i == 3 {
			state, revision = "blocked", 7
		}
		if _, err := pool.Exec(ctx, `INSERT INTO supivpn.issued_profiles(profile_id,secret_hash,subject_hash,state,revision) VALUES($1,$2,$3,$4,$5)`, credentials[i].ID, digest[:], subjects[i][:], state, revision); err != nil {
			t.Fatal("legacy profile fixture")
		}
	}
	// Include never-used and previously-used-but-pruned profiles. Neither has
	// remaining evidence from which the migration can recover an owner label.
	// Two conflicting audit labels for one hash must not produce a guessed owner.
	for n, entry := range []struct {
		index int
		label string
	}{{0, labels[0]}, {2, "conflict-a"}, {2, "conflict-b"}, {3, labels[3]}, {4, "pruned-owner@example.test"}} {
		ticket := fmt.Sprintf("owner-migration-ticket-%043d", n)
		browser := sha256.Sum256([]byte(ticket))
		conn := postgres.Connection{CID: int64(n + 1), KID: 1}
		if err := s.Register(ctx, actor, conn, ticket, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx, ticket, fmt.Sprintf("owner-request-%d", n), browser); err != nil {
			t.Fatal(err)
		}
		pending, err := s.Lookup(ctx, ticket, browser)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		decision := controller.Authorization{Username: entry.label, SubjectHash: subjects[entry.index], GroupName: coreGroup, MaxConnections: 16, AssertionHash: sha256.Sum256([]byte("assertion-" + ticket)), AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
		if err := s.Complete(ctx, pending, decision); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("verified login fixture", err)
		}
	}
	if _, err := pool.Exec(ctx, "DELETE FROM supivpn.logins WHERE subject_hash=$1", subjects[4][:]); err != nil {
		t.Fatal("prune old owner evidence")
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(p)-'owner_username' ORDER BY profile_id)::text FROM supivpn.issued_profiles p`).Scan(&value); err != nil {
			t.Fatal("snapshot")
		}
		return value
	}
	before := snapshot()
	for range 2 {
		if err := postgres.Migrate(ctx, pool); err != nil {
			t.Fatal("upgrade", err)
		}
	}
	if before != snapshot() {
		t.Fatal("migration changed profile credential, owner hash, state, revision or creation time")
	}
	// Labels survive deletion of every temporary authentication record.
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.logins CASCADE"); err != nil {
		t.Fatal("prune fixture")
	}
	for i, c := range credentials {
		p, err := s.ProfileState(ctx, c.ID)
		if err != nil || p.OwnerUsername != labels[i] {
			t.Fatalf("unexpected label for fixture %d", i)
		}
		digest, _ := c.Digest()
		var valid bool
		if err := pool.QueryRow(ctx, "SELECT supivpn.profile_proof_valid($1,$2)", c.ID, digest[:]).Scan(&valid); err != nil || valid != (i != 3) {
			t.Fatal("existing profile proof or block no longer works")
		}
	}
}
