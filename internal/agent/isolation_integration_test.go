// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

type isolatedPower struct {
	*recoveryStub
	excluded string
	observe  func()
}

func (f *isolatedPower) Managed(node string) bool {
	return node != f.excluded && f.recoveryStub.Managed(node)
}
func (f *isolatedPower) Power(ctx context.Context, node string) (string, error) {
	state, err := f.recoveryStub.Power(ctx, node)
	if f.observe != nil {
		f.observe()
	}
	return state, err
}

func TestComponentDatabaseIsolation(t *testing.T) {
	admin, _ := integrationDatabase(t)
	ctx := context.Background()
	exec := func(q string) {
		t.Helper()
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatalf("isolated fixture setup: %v", err)
		}
	}
	exec(`DROP SCHEMA supivpn CASCADE; DROP TABLE public.supivpn_schema_migrations;
        CREATE ROLE supivpn_owner NOLOGIN;
        CREATE ROLE supivpn_public_test LOGIN;
        ALTER ROLE supivpn_public_test SET search_path=supivpn,public;
        CREATE ROLE supivpn_agent_test LOGIN;
        CREATE ROLE supivpn_recovery_test LOGIN;
        REVOKE ALL ON DATABASE supivpn_test FROM PUBLIC;
        REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        GRANT CONNECT ON DATABASE supivpn_test TO supivpn_public_test,supivpn_agent_test,supivpn_recovery_test;
        GRANT CREATE ON DATABASE supivpn_test TO supivpn_owner;
        GRANT USAGE,CREATE ON SCHEMA public TO supivpn_owner`)
	t.Cleanup(func() {
		exec(`DROP SCHEMA IF EXISTS supivpn CASCADE; DROP TABLE IF EXISTS public.supivpn_schema_migrations;
        DROP OWNED BY supivpn_public_test,supivpn_agent_test,supivpn_recovery_test,supivpn_owner;
        DROP ROLE supivpn_public_test,supivpn_agent_test,supivpn_recovery_test,supivpn_owner`)
	})
	if err := postgres.MigrateAsOwner(ctx, admin); err != nil {
		t.Fatal(err)
	}
	roles := postgres.RuntimeRoles{Public: "supivpn_public_test", Agent: "supivpn_agent_test", Recovery: "supivpn_recovery_test"}
	for range 2 {
		if err := postgres.GrantRuntimeRoles(ctx, admin, roles); err != nil {
			t.Fatal(err)
		}
	}
	open := func(name string) *pgxpool.Pool {
		t.Helper()
		u, err := url.Parse(os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
		if err != nil {
			t.Fatal("invalid test URL")
		}
		u.User = url.User(name)
		p, err := postgres.Open(ctx, u.String())
		if err != nil {
			t.Fatal("cannot open restricted local connection")
		}
		t.Cleanup(p.Close)
		return p
	}
	public, agent, recovery := open(roles.Public), open(roles.Agent), open(roles.Recovery)
	securityMetadata := func() string {
		t.Helper()
		var metadata string
		if err := admin.QueryRow(ctx, `SELECT md5(jsonb_agg(jsonb_build_array(
			p.proname,p.proowner,p.prosecdef,p.proconfig,p.proacl) ORDER BY p.proname)::text)
			FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
			WHERE n.nspname='supivpn' AND p.proname NOT LIKE 'profile_%'`).Scan(&metadata); err != nil {
			t.Fatal("cannot inspect disposable function ownership and grants")
		}
		return metadata
	}
	beforeUpgrade := securityMetadata()
	restoreSchema9Functions(t, admin)
	for _, component := range []struct {
		pool *pgxpool.Pool
		kind postgres.Component
	}{{public, postgres.Public}, {agent, postgres.AgentAPI}, {recovery, postgres.Recovery}} {
		if postgres.CheckPrivileges(ctx, component.pool, component.kind) == nil {
			t.Fatal("isolated runtime accepted schema 9 without heartbeat fix")
		}
	}
	for range 2 {
		if err := postgres.MigrateAsOwner(ctx, admin); err != nil {
			t.Fatal("isolated schema 9 to 10 upgrade failed", err)
		}
		if securityMetadata() != beforeUpgrade {
			t.Fatal("function upgrade changed owners, security mode, search path or runtime grants")
		}
	}
	if err := postgres.GrantRuntimeRoles(ctx, admin, roles); err != nil {
		t.Fatal(err)
	}
	f := &isolatedPower{recoveryStub: &recoveryStub{power: map[string]string{"node-a": "running", "node-b": "running"}, starts: map[string]int{}, stops: map[string]int{}}}
	pub, err := postgres.NewIsolated(ctx, public, postgres.Public, nil)
	if err != nil {
		t.Fatal("public privileges", err)
	}
	ag, err := postgres.NewIsolated(ctx, agent, postgres.AgentAPI, nil)
	if err != nil {
		t.Fatal("agent privileges", err)
	}
	t.Run("heartbeat-after-row-lock", func(t *testing.T) {
		testHeartbeatRechecksConcurrentNodeChange(t, admin, ag)
	})
	rec, err := postgres.NewIsolated(ctx, recovery, postgres.Recovery, f)
	if err != nil {
		t.Fatal("recovery privileges", err)
	}
	if _, err := postgres.NewIsolated(ctx, admin, postgres.Public, nil); err == nil {
		t.Fatal("superuser accepted for public runtime")
	}
	if _, err := postgres.NewIsolated(ctx, recovery, postgres.Public, nil); err == nil {
		t.Fatal("recovery login accepted for public runtime")
	}
	if _, err := postgres.NewIsolated(ctx, public, postgres.Public, f); err == nil {
		t.Fatal("public accepted a power driver")
	}
	denied := func(p *pgxpool.Pool, q string) {
		t.Helper()
		_, err := p.Exec(ctx, q)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("expected permission denial for %s", q)
		}
	}
	for _, q := range []string{
		"UPDATE supivpn.nodes SET lease_expires_at='epoch'", "UPDATE supivpn.nodes SET healthy_since=clock_timestamp()",
		"UPDATE supivpn.nodes SET fence_state='stopped'", "DELETE FROM supivpn.nodes",
		"INSERT INTO supivpn.nodes(node_id,generation) VALUES('forged','g')",
		"UPDATE supivpn.node_recovery SET phase='start',stop_reserved=true", "DELETE FROM supivpn.node_recovery_stops",
		"INSERT INTO supivpn.node_maintenance(operation_id,node_id,generation,reason,expires_at) VALUES(repeat('x',32),'a','g','x',now())",
		"SELECT supivpn.agent_rotate('forged','','g')", "SELECT supivpn.agent_heartbeat('node-a','g',true)",
		"SELECT supivpn.prune_auth(100)", "SET ROLE supivpn_owner", "TRUNCATE supivpn.assertions",
		"DELETE FROM supivpn.assertions", "CREATE TABLE supivpn.forbidden(id int)",
	} {
		denied(public, q)
	}
	for _, q := range []string{"UPDATE supivpn.nodes SET fence_state='stopped'", "DELETE FROM supivpn.node_recovery_starts", "UPDATE supivpn.logins SET group_name='forged'", "SELECT supivpn.prune_auth(100)"} {
		denied(agent, q)
	}
	for _, q := range []string{"UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()+interval '1 hour'", "UPDATE supivpn.logins SET group_name='forged'", "DELETE FROM supivpn.assertions", "SELECT supivpn.agent_heartbeat('node-a','g',true)"} {
		denied(recovery, q)
	}
	t.Run("profile-role-boundaries", func(t *testing.T) {
		proof, e := profile.NewCredential()
		if e != nil {
			t.Fatal(e)
		}
		owner := sha256.Sum256([]byte("profile-owner"))
		if e = pub.CreateProfile(ctx, proof, owner); e != nil {
			t.Fatal("public issuance", e)
		}
		denied(agent, "SELECT secret_hash FROM supivpn.issued_profiles")
		denied(public, "UPDATE supivpn.issued_profiles SET state='blocked'")
		denied(recovery, "UPDATE supivpn.issued_profiles SET subject_hash=decode(repeat('00',32),'hex')")
		digest, _ := proof.Digest()
		var valid bool
		if e = agent.QueryRow(ctx, "SELECT supivpn.profile_proof_valid($1,$2)", proof.ID, digest[:]).Scan(&valid); e != nil || !valid {
			t.Fatal("restricted proof check", e)
		}
		if e = public.QueryRow(ctx, "SELECT supivpn.profile_owner_active($1,$2)", proof.ID, owner[:]).Scan(&valid); e != nil || !valid {
			t.Fatal("restricted owner check", e)
		}
		if _, e = rec.SetProfileState(ctx, proof.ID, "blocked", 1); e != nil {
			t.Fatal("operator block", e)
		}
		if e = agent.QueryRow(ctx, "SELECT supivpn.profile_is_active($1)", proof.ID).Scan(&valid); e != nil || valid {
			t.Fatal("blocked profile admitted", e)
		}
	})
	actor := postgres.Agent{NodeID: "node-a", Generation: "g1"}
	conn := postgres.Connection{CID: 1, KID: 1}
	ticket := strings.Repeat("a", 43)
	browser := sha256.Sum256([]byte("browser"))
	for _, node := range []string{"node-a", "node-b"} {
		if err := ag.RotateNode(ctx, node, "", "g1"); err != nil {
			t.Fatal("agent rotation", err)
		}
		if err := ag.HeartbeatStatus(ctx, postgres.Agent{NodeID: node, Generation: "g1"}, true); err != nil {
			t.Fatal("heartbeat", err)
		}
	}
	if err := ag.Register(ctx, actor, conn, ticket, time.Minute); err != nil {
		t.Fatal("register", err)
	}
	if err := pub.Start(ctx, ticket, "request", browser); err != nil {
		t.Fatal("start", err)
	}
	pending, err := pub.Lookup(ctx, ticket, browser)
	if err != nil {
		t.Fatal("lookup", err)
	}
	now := time.Now()
	d := controller.Authorization{Username: "alice", SubjectHash: sha256.Sum256([]byte("alice")), MaxConnections: 1, AssertionHash: sha256.Sum256([]byte("assertion")), GroupName: "admins-vpn", AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
	if err := pub.Complete(ctx, pending, d); !errors.Is(err, controller.ErrDecisionPending) {
		t.Fatal("complete", err)
	}
	decision, err := ag.Fetch(ctx, actor, conn)
	if err != nil || decision.Username != "alice" {
		t.Fatal("fetch", err)
	}
	if err := ag.Acknowledge(ctx, actor, decision.ID, postgres.Applied); err != nil {
		t.Fatal("ack", err)
	}
	if _, err := rec.Prune(ctx, 100); err != nil {
		t.Fatal("restricted cleanup", err)
	}
	profiles := postgres.NewProfileBackend(pub, time.Minute)
	profileTicket := "profile_" + strings.Repeat("p", 43)
	if err := profiles.Start(ctx, profileTicket, "profile-request", browser); err != nil {
		t.Fatal("profile start", err)
	}
	pp, err := profiles.Lookup(ctx, profileTicket, browser)
	if err != nil {
		t.Fatal("profile lookup", err)
	}
	d.AssertionHash = sha256.Sum256([]byte("profile-assertion"))
	if err := profiles.Complete(ctx, pp, d); err != nil {
		t.Fatal("profile complete", err)
	}
	if err := ag.Cancel(ctx, actor, conn); err != nil {
		t.Fatal("cancel", err)
	}
	exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
	state, err := rec.Operate(ctx, postgres.OperatorRequest{Action: "maintenance-begin", NodeID: "node-a", ExpectedGeneration: "g1", RequestID: strings.Repeat("a", 32), Reason: "local-isolation-test"})
	if err != nil || state.Maintenance == nil {
		t.Fatal("restricted maintenance begin", err)
	}
	if _, err = rec.Operate(ctx, postgres.OperatorRequest{Action: "maintenance-end", NodeID: "node-a", ExpectedGeneration: "g1", MaintenanceID: state.Maintenance.ID, RequestID: strings.Repeat("b", 32), Reason: "local-isolation-test"}); err != nil {
		t.Fatal("restricted maintenance end", err)
	}
	exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
	// Auth rows are not fencing instructions; only the independent recovery
	// role can observe, reserve and confirm power transitions.
	if err := ag.HeartbeatStatus(ctx, postgres.Agent{NodeID: "node-b", Generation: "g1"}, true); err != nil {
		t.Fatal(err)
	}
	if len(f.stops) != 0 {
		t.Fatal("heartbeat performed fencing")
	}
	step := func() {
		t.Helper()
		exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
		if err := rec.FenceExpired(ctx); err != nil {
			t.Fatal(err)
		}
	}
	step()
	step()
	if f.stops["node-a"] != 1 {
		t.Fatal("independent recovery did not stop expired node")
	}
	if err := ag.RotateNode(ctx, "node-a", "g1", "g2"); !errors.Is(err, postgres.ErrGeneration) {
		t.Fatal("rotation bypassed fencing")
	}
	f.power["node-a"] = "stopped"
	step()
	step()
	if f.starts["node-a"] != 1 {
		t.Fatal("confirmed stop did not allow start")
	}
	f.power["node-a"] = "running"
	step()
	if err := ag.RotateNode(ctx, "node-a", "g1", "g2"); err != nil {
		t.Fatal("post-fence rotation", err)
	}
	if err := ag.RotateNode(ctx, "node-a", "g2", "g1"); !errors.Is(err, postgres.ErrGeneration) {
		t.Fatal("generation reused")
	}
	if err := ag.HeartbeatStatus(ctx, postgres.Agent{NodeID: "node-a", Generation: "g2"}, true); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
	step()
	// A single accidental extra grant is a startup failure, not a warning.
	exec("GRANT UPDATE(lease_expires_at) ON supivpn.nodes TO supivpn_public_test")
	if postgres.CheckPrivileges(ctx, public, postgres.Public) == nil {
		t.Fatal("excess column privilege accepted")
	}
	if err := postgres.GrantRuntimeRoles(ctx, admin, roles); err != nil {
		t.Fatal(err)
	}
	if postgres.CheckPrivileges(ctx, public, postgres.Public) != nil {
		t.Fatal("restricted role did not recover")
	}
	exec("GRANT pg_read_all_stats TO supivpn_public_test WITH INHERIT TRUE, SET FALSE")
	if postgres.CheckPrivileges(ctx, public, postgres.Public) == nil {
		t.Fatal("inherited role accepted without SET permission")
	}
	exec("REVOKE pg_read_all_stats FROM supivpn_public_test")
	for _, scenario := range []string{"lease-renewed-during-observation", "unmanaged-witness", "start-without-stop-reservation"} {
		t.Run(scenario, func(t *testing.T) {
			exec("TRUNCATE supivpn.nodes CASCADE")
			f.excluded, f.observe = "", nil
			f.starts, f.stops = map[string]int{}, map[string]int{}
			f.power = map[string]string{"node-a": "running", "node-b": "running"}
			for _, node := range []string{"node-a", "node-b"} {
				if err := ag.RotateNode(ctx, node, "", "g1"); err != nil {
					t.Fatal(err)
				}
			}
			exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'; UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
			step()
			switch scenario {
			case "lease-renewed-during-observation":
				f.observe = func() {
					exec("UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE node_id='node-a'")
				}
			case "unmanaged-witness":
				f.excluded = "node-b"
			case "start-without-stop-reservation":
				exec("UPDATE supivpn.node_recovery SET phase='start',stop_reserved=false; UPDATE supivpn.nodes SET fence_state='stopped' WHERE node_id='node-a'")
				f.power["node-a"] = "stopped"
			}
			step()
			if len(f.stops) != 0 || len(f.starts) != 0 {
				t.Fatal("recovery bypassed independent power guards")
			}
		})
	}
}
