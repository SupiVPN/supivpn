// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"supivpn/internal/postgres"
)

func TestAuditUsernameIntegration(t *testing.T) {
	groups := []string{coreGroup, devGroup}
	f := newGroupLifecycleFixture(t, groups, groups, groups)
	logs := captureAudit(t, f.agents[:]...)
	for i, username := range []string{"alice", "bob\"\nforged"} {
		login := f.begin(t, i, 7, username, coreGroup)
		f.callback(t, login, http.StatusAccepted)
		f.deliver(t, login, coreGroup)
		a := f.agents[i]
		c := a.connections[7]
		if c.username != username { t.Fatal("signed NameID lost across PostgreSQL/API boundary") }
		a.handleEvent(clientEvent{kind:"ESTABLISHED", cid:7})
		a.handleEvent(clientEvent{kind:"DISCONNECT", cid:7})
		for _, event := range []string{"vpn.tunnel_established", "vpn.disconnected"} {
			assertTunnelAudit(t, logs, event, username, coreGroup, c.address.String())
		}
		f.settle(t, login)
	}
	login := f.begin(t, 0, 8, "denied-user", unrelatedGroup)
	f.callback(t, login, http.StatusForbidden)
	f.deliver(t, login, "")
	f.agents[0].handleEvent(clientEvent{kind:"DISCONNECT", cid:8})
	if strings.Contains(logs.String(), "denied-user") { t.Fatal("denied identity disclosed in agent audit") }
}

func TestAuditUsernameMigrationPreservesGrant(t *testing.T) {
	groups := []string{coreGroup}
	f := newGroupLifecycleFixture(t, groups, groups, groups)
	login := f.begin(t, 0, 7, "alice", coreGroup)
	f.callback(t, login, http.StatusAccepted)
	f.deliver(t, login, coreGroup)
	ctx := context.Background()
	// Restore schema 7 in the disposable database, preserving the active grant.
	if _, err := f.pool.Exec(ctx, `ALTER TABLE supivpn.logins DROP COLUMN username;
        DROP FUNCTION supivpn.lock_node(text),supivpn.agent_rotate(text,text,text),supivpn.agent_heartbeat(text,text,boolean),supivpn.prune_auth(integer);
		DELETE FROM public.supivpn_schema_migrations WHERE version>=8`); err != nil { t.Fatal("cannot prepare previous schema") }
	if !f.stores[0].Ready(ctx) { t.Fatal("schema 7 must remain ready during bridge deployment") }
	for range 2 {
		if err := postgres.Migrate(ctx, f.pool); err != nil { t.Fatal(err) }
	}
	var state, username string
	var hash []byte
	if err := f.pool.QueryRow(ctx, "SELECT state,username,subject_hash FROM supivpn.logins WHERE cid=7").Scan(&state, &username, &hash); err != nil { t.Fatal("migrated grant missing") }
	if state != "acknowledged" || username != "" || string(hash) != string(f.agents[0].connections[7].subjectHash[:]) || !f.stores[0].Ready(ctx) {
		t.Fatal("migration changed grant identity or inferred a username")
	}
}
