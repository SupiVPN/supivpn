// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
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

func TestPostgresAgentIdentityIsolation(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal("cannot reset disposable database")
	}
	store := postgres.New(pool)
	connection := postgres.Connection{CID: 7, KID: 2}
	actors := []postgres.Agent{{NodeID: "node-a", Generation: "generation-a"}, {NodeID: "node-b", Generation: "generation-a"}}
	decisions := make([]postgres.Decision, len(actors))
	for i, actor := range actors {
		ticket := strings.Repeat(string(rune('a'+i)), 43)
		browser := sha256.Sum256([]byte(actor.NodeID))
		if store.RotateNode(ctx, actor.NodeID, "", actor.Generation) != nil ||
			store.Register(ctx, actor, connection, ticket, time.Minute) != nil ||
			store.Start(ctx, ticket, "request-"+actor.NodeID, browser) != nil {
			t.Fatal("cannot register independent logins with the same connection IDs")
		}
		pending, err := store.Lookup(ctx, ticket, browser)
		if err != nil {
			t.Fatal("cannot look up login")
		}
		var now time.Time
		if err := pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			t.Fatal("cannot read database clock")
		}
		authorization := controller.Authorization{Username: "test-user", SubjectHash: browser, MaxConnections: 1,
			GroupName: "admins-vpn", AssertionHash: sha256.Sum256([]byte(ticket)),
			AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
		if err := store.Complete(ctx, pending, authorization); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("cannot complete independent login")
		}
		decisions[i], err = store.Fetch(ctx, actor, connection)
		if err != nil || decisions[i].Agent != actor || decisions[i].SubjectHash != browser {
			t.Fatal("decision was not bound to its authenticated node")
		}
	}
	if err := store.Acknowledge(ctx, actors[1], decisions[0].ID, postgres.Applied); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("another node acknowledged a decision with matching connection IDs")
	}
	if err := store.Cancel(ctx, actors[0], connection); err != nil {
		t.Fatal("cannot cancel first node's login")
	}
	if got, err := store.Fetch(ctx, actors[1], connection); err != nil || got != decisions[1] {
		t.Fatal("another node's cancellation changed the decision")
	}
	if err := store.Acknowledge(ctx, actors[1], decisions[1].ID, postgres.Applied); err != nil {
		t.Fatal("bound node cannot acknowledge its decision")
	}
	current := postgres.Agent{NodeID: actors[1].NodeID, Generation: "generation-b"}
	if store.RotateNode(ctx, current.NodeID, actors[1].Generation, current.Generation) != nil ||
		store.Register(ctx, current, connection, strings.Repeat("c", 43), time.Minute) != nil {
		t.Fatal("cannot reuse connection IDs in the new generation")
	}
	if _, err := store.Fetch(ctx, actors[1], connection); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("retired generation fetched a decision")
	}
	if err := store.Acknowledge(ctx, current, decisions[1].ID, postgres.Applied); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("new generation acknowledged an old decision")
	}
	if err := store.Cancel(ctx, actors[1], connection); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("retired generation cancelled a connection")
	}
	if err := store.Register(ctx, current, connection, strings.Repeat("c", 43), time.Minute); err != nil {
		t.Fatal("retired generation changed the current pending login")
	}
}
