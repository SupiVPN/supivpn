// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

func TestPostgresRollingSchemaCompatibility(t *testing.T) {
	p, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(p)
	if _, err := p.Exec(ctx, `TRUNCATE supivpn.nodes,supivpn.assertions CASCADE;
		ALTER TABLE supivpn.logins DROP COLUMN username;
        DROP FUNCTION supivpn.lock_node(text),supivpn.agent_rotate(text,text,text),supivpn.agent_heartbeat(text,text,boolean),supivpn.prune_auth(integer);
		DELETE FROM public.supivpn_schema_migrations WHERE version>=8`); err != nil {
		t.Fatal("cannot prepare disposable schema 7")
	}
	t.Cleanup(func() { if err := postgres.Migrate(ctx, p); err != nil { t.Error("cannot restore test schema", err) } })
	for _, version := range []int{7, 8, 9} {
		if !s.Ready(ctx) { t.Fatalf("schema %d rejected by bridge", version) }
		actor := postgres.Agent{NodeID: fmt.Sprintf("bridge-%d", version), Generation: "generation-a"}
		conn := postgres.Connection{CID: int64(version), KID: 1}
		ticket := strings.Repeat(fmt.Sprint(version), 43)
		browser := sha256.Sum256([]byte("test-browser"))
		if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil { t.Fatal("rotate failed") }
		if err := s.Register(ctx, actor, conn, ticket, time.Minute); err != nil { t.Fatal("register failed") }
		if err := s.Start(ctx, ticket, fmt.Sprintf("bridge-request-%d", version), browser); err != nil { t.Fatal("start failed") }
		pending, err := s.Lookup(ctx, ticket, browser)
		if err != nil { t.Fatal("lookup failed") }
		now := time.Now().UTC()
		d := controller.Authorization{Username: "alice", SubjectHash: sha256.Sum256([]byte(ticket)),
			MaxConnections: 1, GroupName: "admins-vpn", AssertionHash: sha256.Sum256([]byte(ticket)),
			AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
		if err = s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrDecisionPending) { t.Fatal("complete failed") }
		decision, err := s.Fetch(ctx, actor, conn)
		if err != nil || decision.GroupName != "admins-vpn" || decision.SubjectHash != d.SubjectHash { t.Fatal("authorization changed") }
		if (version == 7 && decision.Username != "") || (version >= 8 && decision.Username != "alice") { t.Fatal("audit field compatibility failed") }
		if version == 7 {
			// A busy table must abort the migration instead of blocking heartbeats indefinitely.
			tx, err := p.Begin(ctx)
			if err != nil { t.Fatal("cannot begin lock fixture") }
			if _, err = tx.Exec(ctx, "LOCK TABLE supivpn.logins IN ACCESS SHARE MODE"); err != nil { t.Fatal("cannot lock fixture") }
			migrationErr := postgres.Migrate(ctx, p)
			tx.Rollback(ctx)
			if migrationErr == nil { t.Fatal("blocked migration succeeded") }
			var recorded int
			if err = p.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&recorded); err != nil || recorded != 7 { t.Fatal("failed migration changed ledger") }
			if !s.Ready(ctx) { t.Fatal("failed migration broke bridge") }
			if err = postgres.Migrate(ctx, p); err != nil { t.Fatal("online upgrade failed", err) }
			if err = postgres.Migrate(ctx, p); err != nil { t.Fatal("retry after committed migration failed", err) }
			old, err := s.Fetch(ctx, actor, conn)
			if err != nil || old.ID != decision.ID || old.SubjectHash != decision.SubjectHash { t.Fatal("upgrade lost pending decision") }
			if _,err=p.Exec(ctx,`DROP FUNCTION supivpn.lock_node(text),supivpn.agent_rotate(text,text,text),supivpn.agent_heartbeat(text,text,boolean),supivpn.prune_auth(integer);
                DELETE FROM public.supivpn_schema_migrations WHERE version=9`);err!=nil { t.Fatal("cannot prepare disposable schema 8") }
		}
		if version == 8 {
			if err=postgres.Migrate(ctx,p);err!=nil { t.Fatal("schema 8 to 9 migration failed",err) }
			old,err:=s.Fetch(ctx,actor,conn)
			if err!=nil || old!=decision { t.Fatal("schema 9 upgrade changed live authorization") }
		}
	}
	if _, err := p.Exec(ctx, "INSERT INTO public.supivpn_schema_migrations(version,checksum) VALUES(10,''::bytea)"); err != nil { t.Fatal("cannot prepare future schema") }
	ready := s.Ready(ctx)
	if _, err := p.Exec(ctx, "DELETE FROM public.supivpn_schema_migrations WHERE version=10"); err != nil { t.Fatal("cannot remove future schema fixture") }
	if ready { t.Fatal("unreviewed future schema accepted") }
}
