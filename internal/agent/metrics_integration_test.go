// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

func TestMetricsDatabaseAdmissionAccounting(t *testing.T) {
	p, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(p)
	if _, err := p.Exec(ctx, "TRUNCATE supivpn.nodes,supivpn.logins,supivpn.assertions CASCADE"); err != nil {
		t.Fatal("fixture cleanup failed")
	}
	actor := postgres.Agent{NodeID: "metrics-test-node", Generation: "metrics-generation"}
	if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
		t.Fatal(err)
	}
	ticket := strings.Repeat("a", 43)
	owner := sha256.Sum256([]byte("synthetic-owner"))
	if err := registerOwnedFixture(t, s, ctx, actor, postgres.Connection{CID: 7, KID: 2}, ticket, time.Minute, owner); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Metrics(ctx)
	if err != nil || snap.Nodes[0] != 1 || snap.Logins[0] != 1 || snap.ReservedSlots != 0 {
		t.Fatal("pending snapshot incorrect")
	}
	// Exercise admission using the real backend flow, then expire the node lease.
	browser := sha256.Sum256([]byte("synthetic-browser"))
	if err := s.Start(ctx, ticket, "request", browser); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Lookup(ctx, ticket, browser)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	decision := controller.Authorization{Username: "synthetic-owner", SubjectHash: owner, MaxConnections: 1, GroupName: coreGroup, AssertionHash: sha256.Sum256([]byte("synthetic-assertion")), NotBefore: now.Add(-time.Second), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour), AssertionExpiresAt: now.Add(time.Minute)}
	if err := s.Complete(ctx, pending, decision); !errors.Is(err, controller.ErrDecisionPending) {
		t.Fatal(err)
	}
	d, err := s.Fetch(ctx, actor, postgres.Connection{CID: 7, KID: 2})
	if err != nil {
		t.Fatal("decision unavailable")
	}
	if err := s.Acknowledge(ctx, actor, d.ID, postgres.Applied); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, "UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal("fixture expiry")
	}
	snap, err = s.Metrics(ctx)
	if err != nil || snap.Nodes[1] != 1 || snap.Logins[3] != 1 || snap.ReservedSlots != 1 {
		t.Fatal("expired lease incorrectly released admission slot")
	}
	if _, err := p.Exec(ctx, "UPDATE supivpn.nodes SET fence_state='stopped'"); err != nil {
		t.Fatal("fixture fencing")
	}
	snap, err = s.Metrics(ctx)
	if err != nil || snap.Nodes[3] != 1 || snap.ReservedSlots != 0 || snap.Logins[3] != 1 {
		t.Fatal("fenced snapshot incorrect")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.Metrics(ctx); err == nil {
		t.Fatal("cancelled query succeeded")
	}
}
