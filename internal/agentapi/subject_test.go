// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "supivpn/internal/postgres"
)

func TestSubjectHashDeliveryOptIn(t *testing.T) {
    hash:=sha256.Sum256([]byte("issuer\x00alice"))
    for _,opt:=range []string{"",`,"include_subject":false`,`,"include_subject":true`}{
        for _,denied:=range []bool{false,true}{
            s:=&recordedStore{decision:postgres.Decision{SubjectHash:hash,ID:"d1",Agent:postgres.Agent{NodeID:"n1",Generation:"g1"}}}
            if denied {s.decision.DenialReason="no_vpn_group"}
            w:=httptest.NewRecorder()
            New(s,time.Minute).ServeHTTP(w,requestFor("/agent/v1/fetch",`{"generation":"g1","cid":0,"kid":2`+opt+"}","n1"))
            d,err:=DecodeDecision(w.Body.Bytes())
            if w.Code!=200 || err!=nil {t.Fatal("fetch failed",w.Code,err)}
            want:=""
            if opt==`,"include_subject":true` && !denied {want=hex.EncodeToString(hash[:])}
            if d.SubjectHash!=want {t.Fatal("hash opt-in/denial boundary broken")}
            if want=="" && strings.Contains(w.Body.String(),"subject_hash") {t.Fatal("legacy envelope changed")}
        }
    }
    for _,body:=range []string{
        `{"generation":"g1","cid":0,"kid":2,"include_subject":null}`,
        `{"generation":"g1","cid":0,"kid":2,"include_subject":"true"}`,
        `{"generation":"g1","cid":0,"kid":2,"include_subject":true,"include_subject":false}`,
        `{"generation":"g1","cid":0,"kid":2,"Include_subject":true}`,
    } {
        s:=&recordedStore{}; w:=httptest.NewRecorder()
        New(s,time.Minute).ServeHTTP(w,requestFor("/agent/v1/fetch",body,"n1"))
        if w.Code!=400 || s.calls!=0 {t.Fatal("invalid opt-in accepted")}
    }
    s:=&recordedStore{};w:=httptest.NewRecorder()
    New(s,time.Minute).ServeHTTP(w,requestFor("/agent/v1/heartbeat",`{"generation":"g1","include_subject":false}`,"n1"))
    if w.Code!=400 || s.calls!=0 {t.Fatal("opt-in accepted outside fetch")}
}

func TestRejectMalformedSubjectHash(t *testing.T) {
    for _,hash:=range []string{"",strings.Repeat("0",64),strings.Repeat("A",64),strings.Repeat("x",64),strings.Repeat("a",63)} {
        d:=Decision{ID:"d",NodeID:"n",Generation:"g",SubjectHash:hash}
        data,_:=json.Marshal(d)
        // Explicit empty differs from legacy omission.
        if hash=="" {data=[]byte(strings.Replace(string(data),"{",`{"subject_hash":"",`,1))}
        if _,err:=DecodeDecision(data);err==nil {t.Fatal("malformed hash accepted")}
    }
}

