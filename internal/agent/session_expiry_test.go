// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
    "context"
    "testing"
    "time"
    "supivpn/internal/agentapi"
    "supivpn/internal/agentclient"
)

func TestSessionExpiryIsolatedToClient(t *testing.T) {
    for _, ordering:=range []string{"expiry-first","reauth-first","missing-disconnect","cancel-unavailable"} {
        t.Run(ordering,func(t *testing.T) {
            a,commands:=remoteFixture(t,nil)
            now:=time.Now()
            a.now=func()time.Time{return now}
            cancels:=0
            a.remote.api=remoteAPIFunc(func(_ context.Context,op string,q agentclient.Request)(*agentapi.Decision,error) {
                if op=="fetch" {
                    return allowedRemoteDecision(coreGroup),nil
                }
                if op=="cancel" {
                    if *q.CID!=7 || *q.KID!=2 {t.Fatal("wrong cancelled connection")}
                    cancels++
                    if ordering=="cancel-unavailable" {return nil,&agentclient.Error{Status:503}}
                }
                return nil,nil
            })
            connectRemote(t,a,commands)
            remoteStepNow(a); <-commands
            remoteStepNow(a)
            c:=a.connections[7]
            c.expires=now.Add(time.Minute)
            a.remote.leaseUntil=now.Add(time.Hour)
            other:=&connection{cid:8,kid:4,active:true,expires:now.Add(time.Hour),groupName:coreGroup}
            other.address,_=a.pools.acquire(other.cid,coreGroup)
            a.connections[other.cid]=other
            a.expire()
            if len(commands)!=0 || len(a.remote.jobs)!=0 {t.Fatal("active session started browser authentication")}
            now=c.expires
            if ordering=="expiry-first" {a.expire()}
            if ordering=="reauth-first" {
                a.handleEvent(clientEvent{kind:"REAUTH",cid:7,kid:3})
            }
            remoteStepNow(a)
            a.expire()
            select {case <-a.management.done:t.Fatal("absent user stopped the entire node");default:}
            select {
            case cmd:=<-commands:
                if cmd!="client-kill 7" {t.Fatal("session expiry did not target only its client")}
            default: t.Fatal("session expiry did not close client")
            }
            remoteStepNow(a)
            if !c.closing || other.closing || !other.active || len(a.pools.leases)!=2 || cancels!=0 || len(commands)!=0 {
                t.Fatal("timeout released an unconfirmed slot or affected another user")
            }
            if ordering=="missing-disconnect" {
                now=c.closeBy
                a.expire()
                select {case <-a.management.done:default:t.Fatal("unconfirmed disconnect left node running")}
                if cancels!=0 || len(a.pools.leases)!=2 {t.Fatal("unconfirmed disconnect freed a live slot")}
                return
            }
            a.handleEvent(clientEvent{kind:"DISCONNECT",cid:7})
            if len(a.pools.leases)!=1 || a.connections[8]!=other {t.Fatal("wrong local lease released")}
            remoteStepNow(a)
            if ordering=="cancel-unavailable" {
                now=now.Add(30*time.Second)
                remoteStepNow(a)
                select {case <-a.management.done:default:t.Fatal("unknown cancel outcome left node running")}
                return
            }
            if cancels!=1 || len(a.remote.jobs)!=0 {t.Fatal("confirmed disconnect did not release controller slot")}
            select {case <-a.management.done:t.Fatal("clean timeout stopped the node");default:}
        })
    }
}
