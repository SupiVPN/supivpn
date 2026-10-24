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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

// Reconstruct old deployed schema in the disposable test database only.
func removeProfileSchema(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	_, err := p.Exec(context.Background(), `DROP TABLE IF EXISTS supivpn.profile_bindings,supivpn.issued_profiles,supivpn.profile_imports;
 DROP FUNCTION IF EXISTS supivpn.profile_proof_valid(text,bytea),supivpn.profile_is_active(text),supivpn.profile_owner_active(text,bytea);
 DELETE FROM public.supivpn_schema_migrations WHERE version=11`)
	if err != nil {
		t.Fatal("cannot restore disposable pre-profile schema")
	}
}

// Restore the deployed functions too, not just their ledger version. Replacing
// only their bodies preserves owners and runtime grants for upgrade tests.
func restoreSchema9Functions(t *testing.T, pool *pgxpool.Pool) {
	removeProfileSchema(t, pool)
	t.Helper()
	data, err := os.ReadFile("../postgres/migrations/009_component_isolation.sql")
	if err != nil {
		t.Fatal("cannot read schema 9 fixture")
	}
	var restored strings.Builder
	for _, f := range []struct{ name, signature string }{
		{"agent_heartbeat", "text,text,boolean"}, {"prune_auth", "integer"},
	} {
		_, sql, ok := strings.Cut(string(data), "CREATE FUNCTION supivpn."+f.name)
		if !ok {
			t.Fatal("schema 9 function fixture missing")
		}
		sql, _, ok = strings.Cut(sql, "REVOKE ALL ON FUNCTION supivpn."+f.name+"("+f.signature+") FROM PUBLIC;")
		if !ok {
			t.Fatal("schema 9 function fixture incomplete")
		}
		restored.WriteString("CREATE OR REPLACE FUNCTION supivpn." + f.name + sql)
	}
	if _, err := pool.Exec(context.Background(), restored.String()+
		"DELETE FROM public.supivpn_schema_migrations WHERE version=10"); err != nil {
		t.Fatal("cannot restore disposable schema 9 functions")
	}
}

func TestPostgresRollingSchemaCompatibility(t *testing.T) {
	p, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(p)
	removeProfileSchema(t, p)
	if _, err := p.Exec(ctx, `TRUNCATE supivpn.nodes,supivpn.assertions CASCADE;
		ALTER TABLE supivpn.logins DROP COLUMN username;
        DROP FUNCTION supivpn.lock_node(text),supivpn.agent_rotate(text,text,text),supivpn.agent_heartbeat(text,text,boolean),supivpn.prune_auth(integer);
		DELETE FROM public.supivpn_schema_migrations WHERE version>=8`); err != nil {
		t.Fatal("cannot prepare disposable schema 7")
	}
	t.Cleanup(func() {
		if err := postgres.Migrate(ctx, p); err != nil {
			t.Error("cannot restore test schema", err)
		}
	})
	for _, version := range []int{7, 8, 9, 10, 11} {
		if !s.Ready(ctx) {
			t.Fatalf("schema %d rejected by bridge", version)
		}
		if s.ProfileSchemaReady(ctx) != (version == 11) {
			t.Fatal("profile feature schema gate mismatch")
		}
		actor := postgres.Agent{NodeID: fmt.Sprintf("bridge-%d", version), Generation: "generation-a"}
		conn := postgres.Connection{CID: int64(version), KID: 1}
		ticket := fmt.Sprintf("bridge-ticket-%043d", version)
		browser := sha256.Sum256([]byte("test-browser"))
		if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
			t.Fatal("rotate failed")
		}
		if err := s.Register(ctx, actor, conn, ticket, time.Minute); err != nil {
			t.Fatal("register failed")
		}
		if err := s.Start(ctx, ticket, fmt.Sprintf("bridge-request-%d", version), browser); err != nil {
			t.Fatal("start failed")
		}
		pending, err := s.Lookup(ctx, ticket, browser)
		if err != nil {
			t.Fatal("lookup failed")
		}
		now := time.Now().UTC()
		d := controller.Authorization{Username: "alice", SubjectHash: sha256.Sum256([]byte(ticket)),
			MaxConnections: 1, GroupName: "admins-vpn", AssertionHash: sha256.Sum256([]byte(ticket)),
			AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
		if err = s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("complete failed")
		}
		decision, err := s.Fetch(ctx, actor, conn)
		if err != nil || decision.GroupName != "admins-vpn" || decision.SubjectHash != d.SubjectHash {
			t.Fatal("authorization changed")
		}
		if (version == 7 && decision.Username != "") || (version >= 8 && decision.Username != "alice") {
			t.Fatal("audit field compatibility failed")
		}
		if version == 7 {
			// A busy table must abort the migration instead of blocking heartbeats indefinitely.
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal("cannot begin lock fixture")
			}
			if _, err = tx.Exec(ctx, "LOCK TABLE supivpn.logins IN ACCESS SHARE MODE"); err != nil {
				t.Fatal("cannot lock fixture")
			}
			migrationErr := postgres.Migrate(ctx, p)
			tx.Rollback(ctx)
			if migrationErr == nil {
				t.Fatal("blocked migration succeeded")
			}
			var recorded int
			if err = p.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&recorded); err != nil || recorded != 7 {
				t.Fatal("failed migration changed ledger")
			}
			if !s.Ready(ctx) {
				t.Fatal("failed migration broke bridge")
			}
			if err = postgres.Migrate(ctx, p); err != nil {
				t.Fatal("online upgrade failed", err)
			}
			if err = postgres.Migrate(ctx, p); err != nil {
				t.Fatal("retry after committed migration failed", err)
			}
			old, err := s.Fetch(ctx, actor, conn)
			if err != nil || old.ID != decision.ID || old.SubjectHash != decision.SubjectHash {
				t.Fatal("upgrade lost pending decision")
			}
			removeProfileSchema(t, p)
			if _, err = p.Exec(ctx, `DROP FUNCTION supivpn.lock_node(text),supivpn.agent_rotate(text,text,text),supivpn.agent_heartbeat(text,text,boolean),supivpn.prune_auth(integer);
                DELETE FROM public.supivpn_schema_migrations WHERE version>=9`); err != nil {
				t.Fatal("cannot prepare disposable schema 8")
			}
		}
		if version == 8 {
			if err = postgres.Migrate(ctx, p); err != nil {
				t.Fatal("schema 8 upgrade failed", err)
			}
			old, err := s.Fetch(ctx, actor, conn)
			if err != nil || old != decision {
				t.Fatal("schema 8 upgrade changed live authorization")
			}
			if err := s.Acknowledge(ctx, actor, old.ID, postgres.Applied); err != nil {
				t.Fatal("cannot acknowledge pre-upgrade decision")
			}
			restoreSchema9Functions(t, p)
		}
		if version == 9 {
			// Include live decisions, an acknowledged slot, assertion replay rows
			// and node generation history. A function-only upgrade changes none.
			state := func() string {
				t.Helper()
				var value string
				if err := p.QueryRow(ctx, `SELECT md5(jsonb_build_object(
					'nodes',(SELECT jsonb_agg(to_jsonb(t) ORDER BY node_id) FROM supivpn.nodes t),
					'generations',(SELECT jsonb_agg(to_jsonb(t) ORDER BY node_id,generation) FROM supivpn.node_generations t),
					'logins',(SELECT jsonb_agg(to_jsonb(t) ORDER BY ticket_hash) FROM supivpn.logins t),
					'assertions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY assertion_hash) FROM supivpn.assertions t),
					'ledger',(SELECT jsonb_agg(to_jsonb(t) ORDER BY version) FROM public.supivpn_schema_migrations t WHERE version<=9)
				)::text)`).Scan(&value); err != nil {
					t.Fatal("cannot snapshot disposable upgrade state")
				}
				return value
			}
			before := state()
			for range 2 {
				if err := postgres.Migrate(ctx, p); err != nil {
					t.Fatal("schema 9 to 10 upgrade failed", err)
				}
				if state() != before {
					t.Fatal("function migration changed authorization, replay, generation or old migration data")
				}
			}
			old, err := s.Fetch(ctx, actor, conn)
			if err != nil || old != decision {
				t.Fatal("schema 10 upgrade lost live decision")
			}
			removeProfileSchema(t, p)
		}
		if version == 10 {
			if err := postgres.Migrate(ctx, p); err != nil {
				t.Fatal("schema 10 to 11 upgrade failed", err)
			}
			old, err := s.Fetch(ctx, actor, conn)
			if err != nil || old != decision {
				t.Fatal("profile migration changed an existing authorization")
			}
		}
	}
	if _, err := p.Exec(ctx, "INSERT INTO public.supivpn_schema_migrations(version,checksum) VALUES(12,''::bytea)"); err != nil {
		t.Fatal("cannot prepare future schema")
	}
	ready := s.Ready(ctx)
	if _, err := p.Exec(ctx, "DELETE FROM public.supivpn_schema_migrations WHERE version=12"); err != nil {
		t.Fatal("cannot remove future schema fixture")
	}
	if ready {
		t.Fatal("unreviewed future schema accepted")
	}
}
