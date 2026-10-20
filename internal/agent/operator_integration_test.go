// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only


//go:build integration

package agent

import (
 "context"
 "errors"
 "fmt"
 "strings"
 "sync"
 "testing"

 "supivpn/internal/postgres"
)

func TestOperatorRecoveryIntegration(t *testing.T){
 pool,replica:=integrationDatabase(t)
 ctx:=context.Background()
 f:=&recoveryStub{}
 s:=postgres.NewWithFencer(pool,f)
 exec:=func(q string,args ...any){t.Helper();if _,e:=pool.Exec(ctx,q,args...);e!=nil{t.Fatal(e)}}
 status:=func(n string)postgres.OperatorState{
  t.Helper();r,e:=s.Operate(ctx,postgres.OperatorRequest{Action:"status",NodeID:n});if e!=nil{t.Fatal(e)};return r
 }
 counter:=0
 req:=func(action,node string)postgres.OperatorRequest{
  counter++
  state:=status(node)
  q:=postgres.OperatorRequest{Action:action,NodeID:node,ExpectedGeneration:state.Generation,
    RequestID:fmt.Sprintf("%032d",counter),Reason:"test-incident"}
  if strings.HasPrefix(action,"recovery-") && state.Recovery!=nil{
   q.RecoveryID=state.Recovery.ID;q.ExpectedRevision=state.Recovery.Revision
  }
  if state.Maintenance!=nil{q.MaintenanceID=state.Maintenance.ID}
  return q
 }
 apply:=func(q postgres.OperatorRequest)postgres.OperatorState{
  t.Helper();r,e:=s.Operate(ctx,q);if e!=nil{t.Fatalf("%s: %v",q.Action,e)};return r
 }
 refused:=func(q postgres.OperatorRequest){
  t.Helper();if _,e:=s.Operate(ctx,q);e==nil{t.Fatal("unsafe operator request accepted:",q.Action)}
 }
 step:=func(){
  t.Helper();exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
  if e:=s.FenceExpired(ctx);e!=nil{t.Fatal(e)}
 }
 reset:=func(){
  exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes CASCADE")
  f.power=map[string]string{"node-a":"running","node-b":"running","node-c":"running"}
  f.starts,f.stops,f.failStart=map[string]int{},map[string]int{},false
  for _,n:=range []string{"node-a","node-b","node-c"}{if e:=s.RotateNode(ctx,n,"","old");e!=nil{t.Fatal(e)}}
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
 }
 block:=func(){
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  step();step()
  exec("UPDATE supivpn.node_recovery SET deadline='epoch'")
  step()
  if status("node-a").Recovery.Phase!="blocked"{t.Fatal("fixture not blocked")}
 }
 t.Cleanup(func(){exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests")})
 t.Run("maintenance-survives-timeout-and-serializes-cluster",func(t *testing.T){
  reset()
  q:=req("maintenance-begin","node-a");state:=apply(q)
  apply(q) // lost response: same operation, no second lock
  if state.Maintenance.ID!=q.RequestID{t.Fatal("lock identity changed")}
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  for range 3{step()}
  if len(f.stops)!=0{t.Fatal("maintenance caused fencing")}
  other:=req("maintenance-begin","node-b");other.MaintenanceID="";refused(other)
  exec("UPDATE supivpn.node_maintenance SET expires_at='epoch'")
  step()
  refused(postgres.OperatorRequest{Action:"maintenance-check",NodeID:"node-a",MaintenanceID:q.RequestID})
  if status("node-a").Maintenance==nil || len(f.stops)!=0{t.Fatal("expired maintenance auto-released")}
  apply(req("maintenance-renew","node-a"))
  apply(postgres.OperatorRequest{Action:"maintenance-check",NodeID:"node-a",MaintenanceID:q.RequestID})
  refused(req("maintenance-end","node-a"))
  if e:=s.RotateNode(ctx,"node-a","old","new");e!=nil{t.Fatal(e)}
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute' WHERE node_id='node-a'")
  end:=req("maintenance-end","node-a")
  apply(end);apply(end)
  if status("node-a").Maintenance!=nil{t.Fatal("healthy maintenance did not end")}
  refused(q) // completed begin may not reopen on replay
 })
 t.Run("maintenance-replacement-is-bound-to-one-terminated-predecessor",func(t *testing.T){
  reset();m:=apply(req("maintenance-begin","node-a")).Maintenance
  q:=req("maintenance-replace","new-node")
  refused(q) // old node still running
  f.power["node-a"]="stopped";refused(q)
  f.power["node-a"]="terminated";apply(q);apply(q)
  apply(postgres.OperatorRequest{Action:"maintenance-check",NodeID:"new-node",MaintenanceID:m.ID})
  refused(postgres.OperatorRequest{Action:"maintenance-check",NodeID:"node-b",MaintenanceID:m.ID})
  refused(postgres.OperatorRequest{Action:"maintenance-check",NodeID:"node-a",MaintenanceID:m.ID})
  refused(req("maintenance-replace","second-new-node"))
  refused(req("maintenance-end","new-node"))
  if e:=s.RotateNode(ctx,"new-node","","new");e!=nil{t.Fatal(e)}
  f.power["new-node"]="running"
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute' WHERE node_id='new-node'")
  apply(req("maintenance-end","new-node"))
 })
 t.Run("cold-bootstrap-and-exact-generation",func(t *testing.T){
  reset();q:=req("maintenance-begin","new-node");apply(q)
  stale:=req("maintenance-renew","new-node")
  if e:=s.RotateNode(ctx,"new-node","","new");e!=nil{t.Fatal(e)}
  refused(stale)
  f.power["new-node"]="running"
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute' WHERE node_id='new-node'")
  apply(req("maintenance-end","new-node"))
 })
 t.Run("maintenance-cannot-interrupt-active-or-blocked-recovery",func(t *testing.T){
  reset();exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  step();refused(req("maintenance-begin","node-b"));step()
  exec("UPDATE supivpn.node_recovery SET deadline='epoch'");step()
  refused(req("maintenance-begin","node-b"))
 })
 t.Run("completed-job-with-inflight-call-still-blocks-maintenance",func(t *testing.T){
  reset();block()
  exec("UPDATE supivpn.node_recovery SET phase='complete',inflight_until=clock_timestamp()+interval '1 minute'")
  refused(req("maintenance-begin","node-b"))
 })
 t.Run("lost-stop-response-keeps-reservation-and-can-resume-after-proof",func(t *testing.T){
  reset()
  failing:=postgres.NewWithFencer(pool,&lostStopReply{f})
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  step()
  exec("UPDATE supivpn.node_recovery SET next_at='epoch'")
  if e:=failing.FenceExpired(ctx);e==nil{t.Fatal("lost response not reported")}
  if !status("node-a").Recovery.StopReserved || status("node-a").HourlyStops!=1{t.Fatal("uncertain Stop forgotten")}
  exec("UPDATE supivpn.node_recovery SET deadline='epoch'");step()
  f.power["node-a"]="stopped"
  apply(req("recovery-resume","node-a"));step()
  if f.starts["node-a"]!=1{t.Fatal("confirmed owned stop not resumed")}
 })
 t.Run("cloud-observation-error-never-resolves-blocked",func(t *testing.T){
  reset();block();q:=req("recovery-resolve","node-a")
  failing:=postgres.NewWithFencer(pool,&auditUnavailablePower{f})
  if _,e:=failing.Operate(ctx,q);e==nil{t.Fatal("unavailable EC2 treated as stopped")}
  if status("node-a").Recovery.Phase!="blocked" || status("node-a").FenceState!="stopping"{t.Fatal("unknown node released")}
 })
 t.Run("resume-running-keeps-rotation-closed-until-confirmed-stop",func(t *testing.T){
  reset();block();f.power["node-a"]="running"
  apply(req("recovery-resume","node-a"))
  if e:=s.RotateNode(ctx,"node-a","old","new");!errors.Is(e,postgres.ErrGeneration){t.Fatal("unknown Stop allowed generation rotation")}
  step();step()
  if f.stops["node-a"]!=2 || status("node-a").HourlyStops!=2{t.Fatal("reviewed retry not budgeted")}
 })
 t.Run("resume-uses-snapshot-quiescence-and-idempotency",func(t *testing.T){
  reset();block()
  q:=req("recovery-resume","node-a")
  stale:=q;stale.ExpectedRevision--;refused(stale)
  stale=q;stale.ExpectedGeneration="wrong";refused(stale)
  stale=q;stale.RecoveryID="wrong";refused(stale)
  f.power["node-a"]="stopped"
  exec("UPDATE supivpn.node_recovery SET inflight_until=clock_timestamp()+interval '1 minute'")
  refused(q)
  exec("UPDATE supivpn.node_recovery SET inflight_until='epoch'")
  state:=apply(q);apply(q)
  if state.Recovery.Phase!="start" || state.HourlyStops!=1{t.Fatal("resume forgot safety history")}
  changed:=q;changed.Reason="different";refused(changed)
  step()
  if f.starts["node-a"]!=1{t.Fatal("controlled resume did not start")}
  apply(q);step()
  if f.starts["node-a"]!=1{t.Fatal("replayed operator approval started twice")}
 })
 t.Run("resume-does-not-reset-global-budgets",func(t *testing.T){
  reset();block();f.power["node-a"]="running"
  exec("INSERT INTO supivpn.node_recovery_stops(node_id,attempted_at) SELECT 'node-b',clock_timestamp()-n*interval '1 minute' FROM generate_series(1,2)n")
  refused(req("recovery-resume","node-a"))
  f.power["node-a"]="stopped"
  exec("INSERT INTO supivpn.node_recovery_starts(node_id,attempted_at) SELECT 'node-b',clock_timestamp()-n*interval '1 minute' FROM generate_series(1,3)n")
  refused(req("recovery-resume","node-a"))
  if status("node-a").HourlyStops!=3 || status("node-a").HourlyStarts!=3{t.Fatal("budgets erased")}
  apply(req("recovery-resolve","node-a"))
  if status("node-a").FenceState!="stopped" || status("node-a").HourlyStarts!=3{t.Fatal("resolve reset budget/proof")}
 })
 t.Run("resumed-inspection-honors-delayed-owned-stop",func(t *testing.T){
  reset();block();f.power["node-a"]="running"
  apply(req("recovery-resume","node-a"))
  f.power["node-a"]="stopped" // prior unknown Stop converges after approval
  step()
  if status("node-a").Recovery.Phase!="start"{t.Fatal("owned Stop mistaken for operator stop")}
  step()
  if f.starts["node-a"]!=1 || f.stops["node-a"]!=1{t.Fatal("wrong power action after delayed Stop")}
 })
 t.Run("unproven-stopped-or-transitional-node-cannot-be-resolved",func(t *testing.T){
  reset();block()
  for _,power:=range []string{"running","pending","stopping","shutting-down",""}{
   f.power["node-a"]=power;refused(req("recovery-resolve","node-a"))
  }
  f.power["node-a"]="running"
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch'")
  refused(req("recovery-resume","node-a"))
  if status("node-a").FenceState!="stopping"{t.Fatal("uncertain slots released")}
 })
 t.Run("healthy-new-generation-can-resolve-blocked-verification",func(t *testing.T){
  reset();exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  step();step();f.power["node-a"]="stopped";step();step();step()
  if e:=s.RotateNode(ctx,"node-a","old","new");e!=nil{t.Fatal(e)}
  exec("UPDATE supivpn.node_recovery SET deadline='epoch'");step()
  f.power["node-a"]="running"
  refused(req("recovery-resolve","node-a")) // readiness has not soaked
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute' WHERE node_id='node-a'")
  apply(req("recovery-resolve","node-a"))
  if status("node-a").FenceState!="ready"{t.Fatal("resolution fenced recovered generation")}
 })
 t.Run("concurrent-operators-cannot-acquire-two-locks",func(t *testing.T){
  reset()
  a,b:=req("maintenance-begin","node-a"),req("maintenance-begin","node-b")
  other:=postgres.NewWithFencer(replica,f)
  var wg sync.WaitGroup;errs:=make(chan error,2)
  for i,q:=range []postgres.OperatorRequest{a,b}{wg.Add(1);go func(){defer wg.Done();st:=s;if i==1{st=other};_,e:=st.Operate(ctx,q);errs<-e}()}
  wg.Wait();close(errs);success:=0
  for e:=range errs{if e==nil{success++}else if !errors.Is(e,postgres.ErrConflict){t.Fatal(e)}}
  if success!=1{t.Fatal("more than one maintenance owner")}
 })
}

type lostStopReply struct{ *recoveryStub }
func(f *lostStopReply)Stop(ctx context.Context,n string)error{
 if e:=f.recoveryStub.Stop(ctx,n);e!=nil{return e}
 return errors.New("simulated lost provider response")
}
