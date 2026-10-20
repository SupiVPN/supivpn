// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
    "crypto/sha256"
    "fmt"
    "net/http"
    "testing"
    "time"
    "context"

    "supivpn/internal/controller"
)

func TestOperatorDropUserIntegration(t *testing.T) {
    f:=newGroupLifecycleFixture(t,lifecycleGroups,lifecycleGroups,lifecycleGroups)
    policy:=controllerPolicy(lifecycleConfig(0,lifecycleGroups...))
    policy.MaxConnectionsPerUser=2
    control,err:=controller.New(controller.Config{Policy:policy,PendingSeconds:180,SessionSeconds:900},
        f.app.origin,f.app.sp,f.stores[1],time.Now)
    if err!=nil {t.Fatal(err)}
    f.control=control
    issuer:=f.app.sp.IDPMetadata.EntityID
    var sessions []groupLifecycleLogin
    for node:=range 2 {
        login:=f.begin(t,node,7,"alice","admins-vpn")
        f.callback(t,login,http.StatusAccepted)
        f.deliver(t,login,"admins-vpn")
        if f.agents[node].connections[7].subjectHash!=sha256.Sum256([]byte(issuer+"\x00alice")) {
            t.Fatal("verified subject lost between SAML, PostgreSQL and remote agent")
        }
        sessions=append(sessions,login)
    }
    for node,user:=range []string{"bob","Alice"} {
        login:=f.begin(t,node,8,user,"engineers-production-vpn")
        f.callback(t,login,http.StatusAccepted)
        f.deliver(t,login,"engineers-production-vpn")
    }
    for node,a:=range f.agents {
        q:=userSessionsRequest{Operation:"drop",Username:"alice"}
        reply,err:=a.userSessions(context.Background(),issuer,q)
        if err!=nil || reply.Matched!=1 || reply.Requested!=1 || reply.Closing!=1 || reply.Unidentified!=0 {
            t.Fatal("drop did not match remote SAML identity",err,reply)
        }
        if cmd:=lifecycleCommand(t,f.commands[node]);cmd!="client-kill 7" {t.Fatal("incorrect management target",cmd)}
        reply,err=a.userSessions(context.Background(),issuer,q)
        if err!=nil || reply.Requested!=0 || reply.Matched!=1 {t.Fatal("retry not idempotent")}
        if a.connections[8].closing || len(a.pools.leases)!=2 {t.Fatal("other user or IP lease affected")}
    }
    // Closing tunnels still occupy both global slots, even with a valid new login.
    overLimit:=f.begin(t,1,30,"alice","admins-vpn")
    f.callback(t,overLimit,http.StatusForbidden)
    f.deliver(t,overLimit,"")
    f.disconnect(t,overLimit)
    for _,login:=range sessions { f.disconnect(t,login) }
    for node,a:=range f.agents {
        reply,err:=a.userSessions(context.Background(),issuer,userSessionsRequest{Operation:"status",Username:"alice"})
        if err!=nil || reply.Matched!=0 || reply.Unidentified!=0 {t.Fatal("confirmed disconnect missing")}
        var state string
        if err=f.pool.QueryRow(context.Background(),
            "SELECT state FROM supivpn.logins WHERE node_id=$1 AND generation='g1' AND cid=7 AND kid=2",
            fmt.Sprintf("lifecycle-node-%d",node)).Scan(&state);err!=nil || state!="cancelled" {t.Fatal("slot cancellation missing",err)}
    }
    // This command is a drop, not a denylist: a still-enabled user may reconnect.
    reconnect:=f.begin(t,1,31,"alice","admins-vpn")
    f.callback(t,reconnect,http.StatusAccepted)
    f.deliver(t,reconnect,"admins-vpn")
    f.disconnect(t,reconnect)
}
