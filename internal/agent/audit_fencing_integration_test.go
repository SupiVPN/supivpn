// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only


//go:build integration

package agent

import (
 "context"
 "errors"
 "testing"
 "supivpn/internal/controller"
 "supivpn/internal/postgres"
)

type auditUnavailablePower struct { *recoveryStub }
func(f *auditUnavailablePower)Power(context.Context,string)(string,error){
 return "",errors.New("private provider error")
}

func TestFencingRegressionIntegration(t *testing.T){
 pool,_:=integrationDatabase(t)
 ctx:=context.Background()
 exec:=func(q string,args ...any){t.Helper();if _,e:=pool.Exec(ctx,q,args...);e!=nil{t.Fatal(e)}}
 setup:=func()*recoveryStub{
  exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes CASCADE")
  s:=postgres.New(pool)
  for _,n:=range []string{"node-a","node-b","node-c"}{if e:=s.RotateNode(ctx,n,"","old");e!=nil{t.Fatal(e)}}
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-a'")
  return &recoveryStub{power:map[string]string{"node-a":"running","node-b":"running","node-c":"running"},starts:map[string]int{},stops:map[string]int{}}
 }
 step:=func(s *postgres.Store){
  t.Helper()
  exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
  if e:=s.FenceExpired(ctx);e!=nil{t.Fatal(e)}
 }
 t.Run("stop-only-requires-stable-witness-and-global-budget",func(t *testing.T){
  f:=setup()
  // Hide Start: automatic_recovery=false must retain every fencing guard.
  s:=postgres.NewWithFencer(pool,struct{postgres.Fencer}{f})
  exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id='node-b'")
  exec("UPDATE supivpn.nodes SET healthy_since=NULL WHERE node_id='node-c'")
  step(s);step(s)
  if len(f.stops)!=0{t.Fatal("unready witness permitted stop")}
  exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute' WHERE node_id='node-c'")
  step(s)
  for range 5{
   f.power["node-a"]="running" // failed stop: request success is not proof
   step(s)
  }
  var phase string
  if e:=pool.QueryRow(ctx,"SELECT phase FROM supivpn.node_recovery WHERE node_id='node-a'").Scan(&phase);e!=nil{t.Fatal(e)}
  if f.stops["node-a"]!=3 || f.stops["node-b"]!=0 || phase!="blocked" || len(f.starts)!=0{t.Fatal("stop-only bypassed guards")}
 })
 t.Run("observation-failure-does-not-block-clean-restart",func(t *testing.T){
  f:=&auditUnavailablePower{setup()}
  s:=postgres.NewWithFencer(pool,f)
  if e:=s.FenceExpired(ctx);!errors.Is(e,controller.ErrUnavailable){t.Fatal(e)}
  if e:=s.RotateNode(ctx,"node-a","old","new");e!=nil{t.Fatal("no Stop was reserved:",e)}
  if len(f.stops)!=0 || len(f.starts)!=0{t.Fatal("observation mutated EC2")}
 })
 t.Run("clean-restart-before-stop-invalidates-job",func(t *testing.T){
  f:=setup();s:=postgres.NewWithFencer(pool,f)
  step(s)
  if e:=s.RotateNode(ctx,"node-a","old","new");e!=nil{t.Fatal(e)}
  step(s)
  if len(f.stops)!=0{t.Fatal("stale job stopped new generation")}
 })
}
