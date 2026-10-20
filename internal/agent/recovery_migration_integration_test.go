// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only


//go:build integration

package agent

import(
 "context"
 "testing"
 "supivpn/internal/postgres"
)

func TestRecoveryMigrationPreservesUnknownLegacyStops(t *testing.T){
 pool,_:=integrationDatabase(t);ctx:=context.Background()
 exec:=func(q string,args ...any){t.Helper();if _,e:=pool.Exec(ctx,q,args...);e!=nil{t.Fatal(e)}}
 exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes CASCADE")
 s:=postgres.New(pool)
 for _,n:=range []string{"inspect-node","stop-only-node","stop-node"}{
  if e:=s.RotateNode(ctx,n,"","old");e!=nil{t.Fatal(e)}
 }
 // Recreate schema 6 only in the disposable loopback database.
  exec(`DROP FUNCTION supivpn.lock_node(text),supivpn.agent_heartbeat(text,text,boolean),supivpn.agent_rotate(text,text,text),supivpn.prune_auth(integer);
   DROP TABLE supivpn.node_maintenance,supivpn.operator_requests,supivpn.node_recovery_stops;
  DROP INDEX supivpn.recovery_starts_time;
  ALTER TABLE supivpn.node_recovery DROP COLUMN operation_id,DROP COLUMN revision,
   DROP COLUMN stop_reserved,DROP COLUMN inflight_until,DROP COLUMN reason;
   ALTER TABLE supivpn.logins DROP COLUMN username;
   DELETE FROM public.supivpn_schema_migrations WHERE version>=7;
  UPDATE supivpn.nodes SET fence_state='stopping';
  INSERT INTO supivpn.node_recovery(node_id,generation,phase,deadline)
   VALUES ('inspect-node','old','inspect',clock_timestamp()+interval '1 minute'),
          ('stop-node','old','blocked',clock_timestamp()+interval '1 minute')`)
 if e:=postgres.Migrate(ctx,pool);e!=nil{t.Fatal(e)}
 if e:=postgres.Migrate(ctx,pool);e!=nil{t.Fatal(e)}
 for _,tc:=range []struct{node,phase,fence string;reserved bool;attempts int}{
  {"inspect-node","inspect","ready",false,0},
  {"stop-only-node","blocked","stopping",true,3},
  {"stop-node","blocked","stopping",true,3},
 }{
  var phase,fence string;var reserved,quiet bool;var attempts int
  e:=pool.QueryRow(ctx,`SELECT r.phase,n.fence_state,r.stop_reserved,r.inflight_until>clock_timestamp(),
   (SELECT count(*) FROM supivpn.node_recovery_stops x WHERE x.node_id=n.node_id)
   FROM supivpn.nodes n JOIN supivpn.node_recovery r USING(node_id) WHERE n.node_id=$1`,tc.node).
   Scan(&phase,&fence,&reserved,&quiet,&attempts)
  if e!=nil || phase!=tc.phase || fence!=tc.fence || reserved!=tc.reserved || attempts!=tc.attempts || !quiet{
   t.Fatalf("unsafe legacy migration for %s: %v",tc.node,e)
  }
 }
}
