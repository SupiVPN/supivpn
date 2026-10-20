// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only


package operatorapi

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
 "supivpn/internal/postgres"
)
type stub struct{ calls int; err error }
func(s *stub)Operate(context.Context,postgres.OperatorRequest)(postgres.OperatorState,error){
 s.calls++;return postgres.OperatorState{NodeID:"node-a"},s.err
}
func TestOperatorEnvelopeStrictBoundary(t *testing.T){
 good:=`{"source":"supivpn.operator.v1","action":"status","node_id":"node-a"}`
 s:=&stub{};h:=Handler(s)
 if r,_:=h(context.Background(),json.RawMessage(good));!r.(Reply).OK || s.calls!=1{t.Fatal("direct invocation failed")}
 for _,raw:=range []string{
  `null`,`[]`,`{}`,`{"source":"supivpn.operator.v1","action":null}`,
  strings.Replace(good,`"action":"status"`,`"action":"status","action":"maintenance-begin"`,1),
  strings.Replace(good,`"source"`,`"Source"`,1),
  strings.Replace(good,`"node-a"`,`{"node":"a"}`,1),
  strings.Replace(good,`"node-a"`,`["node-a"]`,1),
  strings.TrimSuffix(good,"}")+`,"requestContext":{}}`,
  strings.TrimSuffix(good,"}")+`,"body":"{}"}`,
  good+good,strings.Repeat(" ",8193)+good,
  strings.Replace(good,"supivpn.operator.v1","aws.events",1),
  strings.TrimSuffix(good,"}")+`,"expected_revision":1.5}`,
 }{
  r,e:=h(context.Background(),json.RawMessage(raw))
  if e!=nil || r.(Reply).OK || s.calls!=1{t.Fatal("malformed envelope reached store")}
 }
 s.err=errors.New("private driver details")
 r,_:=h(context.Background(),json.RawMessage(good))
 b,_:=json.Marshal(r)
 if strings.Contains(string(b),"private") || r.(Reply).Error!="unavailable"{t.Fatal("internal details leaked")}
 s.err=postgres.ErrGeneration
 r,_=h(context.Background(),json.RawMessage(good))
 if r.(Reply).Error!="conflict"{t.Fatal("stale snapshot not refused")}
}
