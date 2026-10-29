// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

// Exercise the combined VM role and the separate Lambda roles against old
// in-flight logins, using only the disposable database's fixture administrator.
func testRemovedUnboundAdmission(t *testing.T, admin *pgxpool.Pool, public, agents *postgres.Store) {
	t.Helper()
	ctx := context.Background()
	for _, stage := range []string{"complete", "fetch", "ack"} {
		t.Run(stage, func(t *testing.T) {
			a := postgres.Agent{NodeID: "removed-" + rand.Text(), Generation: "g1"}
			c := postgres.Connection{CID: 71, KID: 2}
			ticket := (rand.Text() + rand.Text())[:43]
			hash := sha256.Sum256([]byte(ticket))
			owner := sha256.Sum256([]byte(a.NodeID))
			if err := agents.RotateNode(ctx, a.NodeID, "", a.Generation); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := agents.RotateNode(ctx, a.NodeID, a.Generation, "g2"); err != nil {
					t.Error("cleanup", err)
				}
			})
			if !errors.Is(agents.Register(ctx, a, c, ticket, time.Minute), postgres.ErrConflict) {
				t.Fatal("old registration accepted")
			}
			proof := ownedFixtureProof(t, public, owner, ticket)
			if err := agents.RegisterProfile(ctx, a, c, ticket, time.Minute, proof); err != nil {
				t.Fatal(err)
			}
			browser := sha256.Sum256([]byte("browser:" + ticket))
			if err := public.Start(ctx, ticket, "request-"+ticket, browser); err != nil {
				t.Fatal(err)
			}
			pending, err := public.Lookup(ctx, ticket, browser)
			if err != nil {
				t.Fatal(err)
			}
			removeBinding := func() {
				t.Helper()
				// Historical unbound rows have no profile_bindings entry.
				if _, err := admin.Exec(ctx, "DELETE FROM supivpn.profile_bindings WHERE ticket_hash=$1", hash[:]); err != nil {
					t.Fatal("historical login fixture", err)
				}
			}
			if stage == "complete" {
				removeBinding()
			}
			now := time.Now()
			d := controller.Authorization{Username: "test-owner", SubjectHash: owner, GroupName: coreGroup, MaxConnections: 1,
				AssertionHash: sha256.Sum256([]byte(rand.Text())), AssertionExpiresAt: now.Add(time.Minute),
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
			err = public.Complete(ctx, pending, d)
			if stage == "complete" {
				if !errors.Is(err, controller.ErrGroupDenied) {
					t.Fatal("unbound SAML completion accepted", err)
				}
				decision, err := agents.Fetch(ctx, a, c)
				if err != nil || decision.DenialReason != "profile_refused" {
					t.Fatal("missing profile refusal", err)
				}
				return
			}
			if !errors.Is(err, controller.ErrDecisionPending) {
				t.Fatal(err)
			}
			decision, err := agents.Fetch(ctx, a, c)
			if err != nil {
				t.Fatal(err)
			}
			removeBinding()
			if stage == "fetch" {
				_, err = agents.Fetch(ctx, a, c)
			} else {
				err = agents.Acknowledge(ctx, a, decision.ID, postgres.Applied)
			}
			if !errors.Is(err, controller.ErrLoginExpired) {
				t.Fatal("historical unbound grant accepted", err)
			}
		})
	}
}
