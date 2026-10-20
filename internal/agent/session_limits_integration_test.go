// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "sync"
    "testing"
    "time"

    "supivpn/internal/controller"
    "supivpn/internal/postgres"
)

type testNodeFencer struct {
    calls []string
    stopped bool
    err error
    entered, release chan struct{}
}
func (f *testNodeFencer) Managed(string) bool { return true }
func (f *testNodeFencer) Stop(context.Context,string) error {return nil}
func (f *testNodeFencer) Power(_ context.Context, node string) (string, error) {
    f.calls = append(f.calls, node)
    if f.entered != nil { close(f.entered); <-f.release }
    if f.stopped {return "stopped", f.err};return "running",f.err
}

func TestSessionLimitsAndFencingIntegration(t *testing.T) {
    pool, replica := integrationDatabase(t)
    ctx := context.Background()
    a := postgres.Agent{NodeID: "node-a", Generation: "generation-a"}
    b := postgres.Agent{NodeID: "node-b", Generation: "generation-b"}
    f := &testNodeFencer{}
    first, second := postgres.NewWithFencer(pool, f), postgres.New(replica)
    exec := func(sql string, args ...any) {
        t.Helper()
        if _, err := pool.Exec(ctx, sql, args...); err != nil { t.Fatal("local fixture SQL failed") }
    }
    reset := func() {
        exec("TRUNCATE supivpn.node_maintenance,supivpn.operator_requests,supivpn.profile_logins,supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE")
        f.calls, f.stopped, f.err = nil, false, nil
        f.entered, f.release = nil, nil
        for _, node := range []postgres.Agent{a,b} {
            if err := first.RotateNode(ctx, node.NodeID, "", node.Generation); err != nil { t.Fatal(err) }
        }
        exec("UPDATE supivpn.nodes SET healthy_since=clock_timestamp()-interval '1 minute'")
    }
    prepare := func(node postgres.Agent, id int64, limit int) (controller.Pending, controller.Authorization) {
        t.Helper()
        ticket := fmt.Sprintf("test-ticket-%040d", id)
        browser := sha256.Sum256([]byte(ticket))
        conn := postgres.Connection{CID: id, KID: 1}
        if err := first.Register(ctx, node, conn, ticket, time.Minute); err != nil { t.Fatal(err) }
        if err := first.Start(ctx, ticket, fmt.Sprintf("request-%d", id), browser); err != nil { t.Fatal(err) }
        pending, err := second.Lookup(ctx, ticket, browser)
        if err != nil { t.Fatal(err) }
        // Use the same clock as the decision validator at the exact 12h cap.
        // The disposable Docker database can lag the host clock slightly.
        var now time.Time
        if err := pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil { t.Fatal(err) }
        return pending, controller.Authorization{
            SubjectHash: sha256.Sum256([]byte("verified-issuer\x00same-user")), MaxConnections: limit,
            AssertionHash: browser, GroupName: "admins-vpn",
            AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
            NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(12*time.Hour),
        }
    }
    grant := func(node postgres.Agent, id int64, limit int) {
        t.Helper()
        pending, decision := prepare(node,id,limit)
        if err := first.Complete(ctx,pending,decision); !errors.Is(err,controller.ErrDecisionPending) { t.Fatal(err) }
    }
    expectLimit := func(id int64) {
        t.Helper()
        pending, decision := prepare(b,id,1)
        // Changing groups never hides another existing session of this subject.
        decision.GroupName = "engineers-production-vpn"
        if err := second.Complete(ctx,pending,decision); !errors.Is(err,controller.ErrConnectionLimit) {
            t.Fatalf("expected connection limit, got %v",err)
        }
        result, err := second.Fetch(ctx,b,postgres.Connection{CID:id,KID:1})
        if err != nil || result.DenialReason != "connection_limit" || result.GroupName != "" {
            t.Fatal("limit denial was not persisted for the agent")
        }
    }
    t.Run("concurrent-admission-across-replicas-and-nodes",func(t *testing.T) {
        for _, limit := range []int{1,2} {
            reset()
            var pending []controller.Pending
            var decisions []controller.Authorization
            for id:=int64(1);id<=8;id++ {
                node:=a
                if id%2==0 { node=b }
                p,d:=prepare(node,id,limit)
                pending=append(pending,p); decisions=append(decisions,d)
            }
            start:=make(chan struct{})
            results:=make(chan error,8)
            var wg sync.WaitGroup
            for i:=range pending {
                wg.Add(1)
                go func(i int) {
                    defer wg.Done()
                    <-start
                    s:=first
                    if i%2==0 { s=second }
                    results<-s.Complete(ctx,pending[i],decisions[i])
                }(i)
            }
            close(start);wg.Wait();close(results)
            granted,denied:=0,0
            for err:=range results {
                switch {
                case errors.Is(err,controller.ErrDecisionPending): granted++
                case errors.Is(err,controller.ErrConnectionLimit): denied++
                default: t.Fatalf("admission failed: %v",err)
                }
            }
            if granted!=limit || denied!=8-limit { t.Fatalf("limit %d: grants=%d denials=%d",limit,granted,denied) }
        }
    })
    t.Run("unlimited-roundtrip-retains-slot-until-confirmed-disconnect",func(t *testing.T) {
        reset()
        p,d:=prepare(a,1,1)
        d.SessionUnlimited=true
        d.SessionExpiresAt=time.Time{}
        if err:=first.Complete(ctx,p,d);!errors.Is(err,controller.ErrDecisionPending) {t.Fatal(err)}
        got,err:=second.Fetch(ctx,a,postgres.Connection{CID:1,KID:1})
        if err!=nil || !got.SessionUnlimited || !got.SessionExpiresAt.IsZero() {t.Fatalf("unlimited decision roundtrip: %v",err)}
        if err=second.Acknowledge(ctx,a,got.ID,postgres.Applied);err!=nil {t.Fatal(err)}
        exec("UPDATE supivpn.logins SET expires_at=clock_timestamp()-interval '25 hours' WHERE node_id=$1",a.NodeID)
        if _,err=first.Prune(ctx,100);err!=nil {t.Fatal(err)}
        expectLimit(2)
        if err=first.Cancel(ctx,a,postgres.Connection{CID:1,KID:1});err!=nil {t.Fatal(err)}
        grant(b,3,1)
    })
    t.Run("lost-ack-and-confirmed-disconnect",func(t *testing.T) {
        reset();grant(a,1,1)
        expectLimit(2) // A lost grant/ACK response must still reserve a slot.
        if err:=first.Cancel(ctx,a,postgres.Connection{CID:1,KID:1});err!=nil { t.Fatal(err) }
        grant(b,3,1)
    })
    t.Run("pool-exhaustion-denial-releases-reservation",func(t *testing.T) {
        reset();grant(a,1,1)
        d,err:=first.Fetch(ctx,a,postgres.Connection{CID:1,KID:1})
        if err!=nil { t.Fatal(err) }
        if err=first.Acknowledge(ctx,a,d.ID,postgres.Denied);err!=nil { t.Fatal(err) }
        grant(b,2,1)
    })
    t.Run("expired-lease-and-session-do-not-release-slot",func(t *testing.T) {
        reset();grant(a,1,1)
        exec("UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE node_id=$1",a.NodeID)
        exec("UPDATE supivpn.logins SET session_expires_at=clock_timestamp()-interval '1 second',expires_at=clock_timestamp()-interval '25 hours' WHERE node_id=$1",a.NodeID)
        if err:=first.Heartbeat(ctx,a); !errors.Is(err,postgres.ErrGeneration) { t.Fatal("expired lease resurrected") }
        if n,err:=first.Prune(ctx,100);err!=nil || n!=0 { t.Fatal("TTL released an unfenced slot") }
        expectLimit(2)
        if err:=first.FenceExpired(ctx);err!=nil { t.Fatal(err) }
        if len(f.calls)!=1 || f.calls[0]!=a.NodeID { t.Fatal("wrong fencing target") }
        exec("UPDATE supivpn.node_recovery SET next_at='epoch'")
        if err:=first.FenceExpired(ctx);err!=nil { t.Fatal(err) }
        expectLimit(3) // Successful stop request alone is not sufficient.
        if err:=first.RotateNode(ctx,a.NodeID,a.Generation,"new-generation");!errors.Is(err,postgres.ErrGeneration) {
            t.Fatal("node restarted while fencing is pending")
        }
        if err:=first.FenceExpired(ctx);err!=nil || len(f.calls)!=2 { t.Fatal("cooldown did not bound cloud calls") }
        f.stopped=true
        exec("UPDATE supivpn.node_recovery SET next_at='epoch',inflight_until='epoch'")
        if err:=first.FenceExpired(ctx);err!=nil { t.Fatal(err) }
        grant(b,4,1)
        if err:=first.Heartbeat(ctx,a);!errors.Is(err,postgres.ErrGeneration) { t.Fatal("fenced generation resurrected") }
        if err:=first.RotateNode(ctx,a.NodeID,"",a.Generation);!errors.Is(err,postgres.ErrGeneration) {
            t.Fatal("fenced generation bootstrap replay accepted")
        }
        if err:=first.RotateNode(ctx,a.NodeID,a.Generation,"new-generation");err!=nil { t.Fatal(err) }
        if err:=first.Heartbeat(ctx,postgres.Agent{NodeID:a.NodeID,Generation:"new-generation"});err!=nil { t.Fatal(err) }
        if len(f.calls)!=3 { t.Fatal("healthy restarted node fenced") }
    })
    t.Run("fencing-error-retains-slots-and-is-bounded",func(t *testing.T) {
        reset();grant(a,1,1)
        exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id=$1",a.NodeID)
        f.err=errors.New("test provider failure")
        if err:=first.FenceExpired(ctx);!errors.Is(err,controller.ErrUnavailable) { t.Fatal("provider error not opaque") }
        expectLimit(2)
        for range 10 { _=first.FenceExpired(ctx) }
        if len(f.calls)!=1 { t.Fatal("provider outage caused unbounded retries") }
        if err:=first.Heartbeat(ctx,b);err!=nil { t.Fatal("unrelated healthy heartbeat failed") }
    })
    t.Run("parallel-fencing-does-not-duplicate-stop-or-lock-healthy-node",func(t *testing.T) {
        reset();grant(a,1,1)
        exec("UPDATE supivpn.nodes SET lease_expires_at='epoch' WHERE node_id=$1",a.NodeID)
        f.entered, f.release, f.stopped = make(chan struct{}), make(chan struct{}), true
        done:=make(chan error,1)
        go func(){done<-first.FenceExpired(ctx)}()
        select {
        case <-f.entered:
        case <-time.After(5*time.Second): t.Fatal("fencing did not start")
        }
        // Always unblock the mock before leaving this test, including failure.
        defer func(){close(f.release); if err:=<-done;err!=nil {t.Error(err)}}()
        bounded,cancel:=context.WithTimeout(ctx,2*time.Second)
        defer cancel()
        if err:=postgres.NewWithFencer(replica,f).FenceExpired(bounded);err!=nil {t.Fatal(err)}
        if err:=first.Heartbeat(bounded,b);err!=nil {t.Fatal("cloud call blocked healthy heartbeat")}
        expectLimit(2)
        if len(f.calls)!=1 {t.Fatal("parallel controller repeated stop")}
    })
    t.Run("legacy-grants-block-admission-until-drained",func(t *testing.T) {
        reset();grant(a,1,1)
        // Simulate a pre-migration row, retaining the migration's NOT VALID constraint.
        exec(`ALTER TABLE supivpn.logins DROP CONSTRAINT grant_requires_subject;
              UPDATE supivpn.logins SET subject_hash=NULL;
              ALTER TABLE supivpn.logins ADD CONSTRAINT grant_requires_subject
              CHECK (state NOT IN ('decided','acknowledged') OR denial_reason<>'' OR subject_hash IS NOT NULL) NOT VALID`)
        pending,decision:=prepare(b,2,1)
        if err:=second.Complete(ctx,pending,decision);!errors.Is(err,controller.ErrUnavailable) {
            t.Fatal("legacy unaccounted session allowed admission")
        }
        if err:=first.Cancel(ctx,a,postgres.Connection{CID:1,KID:1});err!=nil { t.Fatal(err) }
        if err:=second.Complete(ctx,pending,decision);!errors.Is(err,controller.ErrDecisionPending) {
            t.Fatal("drained legacy session still blocked admission")
        }
    })
}
