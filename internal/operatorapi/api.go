// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package operatorapi handles a small, explicitly privileged operator protocol.
// It has no HTTP routes and must not be attached to the agent/public listeners.
package operatorapi

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "io"
    "slices"

    "supivpn/internal/postgres"
)

const Source = "supivpn.operator.v1"

type Store interface { Operate(context.Context,postgres.OperatorRequest)(postgres.OperatorState,error) }
type Reply struct {
    OK bool `json:"ok"`
    State *postgres.OperatorState `json:"state,omitempty"`
    Error string `json:"error,omitempty"`
}
func Decode(raw []byte)(postgres.OperatorRequest,error) {
    var q postgres.OperatorRequest
    refused:=errors.New("invalid operator request")
    if len(raw)>8192{return q,refused}
    d:=json.NewDecoder(bytes.NewReader(raw))
    token,err:=d.Token();if err!=nil || token!=json.Delim('{'){return q,refused}
    fields:=map[string]json.RawMessage{}
    for d.More(){
        token,err=d.Token();key,ok:=token.(string)
        if err!=nil || !ok || !slices.Contains([]string{"source","action","node_id","expected_generation",
            "recovery_id","expected_revision","maintenance_id","request_id","reason"},key){return q,refused}
        if _,exists:=fields[key];exists{return q,refused}
        var value json.RawMessage
        if d.Decode(&value)!=nil || len(value)==0 || value[0]=='{' || value[0]=='[' || string(value)=="null"{return q,refused}
        fields[key]=value
    }
    if token,err=d.Token();err!=nil || token!=json.Delim('}'){return q,refused}
    if _,err=d.Token();err!=io.EOF{return q,refused}
    var source string
    if json.Unmarshal(fields["source"],&source)!=nil || source!=Source{return q,refused}
    delete(fields,"source")
    b,err:=json.Marshal(fields);if err!=nil || json.Unmarshal(b,&q)!=nil{return q,refused}
    return q,nil
}
func Handler(s Store)func(context.Context,json.RawMessage)(any,error){
    return func(ctx context.Context,raw json.RawMessage)(any,error){
        q,err:=Decode(raw)
        if err!=nil || s==nil{return Reply{Error:"invalid_request"},nil}
        state,err:=s.Operate(ctx,q)
        if err!=nil{
            code:="unavailable"
            if errors.Is(err,postgres.ErrConflict) || errors.Is(err,postgres.ErrGeneration){code="conflict"}
            return Reply{Error:code},nil
        }
        return Reply{OK:true,State:&state},nil
    }
}
