// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

func TestHeartbeatBudgetAndDeadline(t *testing.T) {
	now := time.Now()
	calls := 0
	a, _ := remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
		if op != "heartbeat" || q.Generation != "g1" || q.CID != nil { t.Fatal("heartbeat not node-scoped") }
		calls++
		return nil, nil
	}))
	a.now = func() time.Time { return now }
	a.remote.leaseUntil, a.remote.heartbeatDue = now.Add(40*time.Second), now.Add(15*time.Second)
	start := now
	for i := 0; i < 600; i++ {
		now = start.Add(time.Duration(i)*100*time.Millisecond)
		a.remoteStep(context.Background())
	}
	if calls != 3 { t.Fatalf("idle heartbeat budget: got %d calls in 60s", calls) }
	if !a.remote.leaseUntil.Equal(start.Add(85*time.Second)) { t.Fatal("renewal deadline changed") }
}

func TestHeartbeatOutageStopsPairWithoutWaitingForHTTP(t *testing.T) {
	var clock atomic.Int64
	start := time.Now()
	entered, release := make(chan struct{}), make(chan struct{})
	a, _ := remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
		if op != "heartbeat" { t.Error("unexpected operation") }
		close(entered)
		<-release
		return nil, nil
	}))
	a.now = func() time.Time { return start.Add(time.Duration(clock.Load())) }
	a.remote.leaseUntil, a.remote.heartbeatDue = start.Add(40*time.Second), start
	done := make(chan struct{})
	go func() { defer close(done); a.remoteStep(context.Background()) }()
	<-entered
	clock.Store(int64(40*time.Second))
	a.expire()
	select {
	case <-a.management.done:
	default: t.Fatal("expired node kept serving while heartbeat was stalled")
	}
	before := a.remote.leaseUntil
	close(release)
	<-done
	if a.remote.leaseUntil != before { t.Fatal("late heartbeat resurrected expired node") }
}

func TestRemoteActiveDisconnectReleasesSlot(t *testing.T) {
	var cancelCalls int
	a, commands := remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
		if op == "fetch" { return allowedRemoteDecision(coreGroup), nil }
		if op == "cancel" { cancelCalls++ }
		return nil, nil
	}))
	connectRemote(t, a, commands)
	remoteStepNow(a)
	<-commands
	remoteStepNow(a)
	if len(a.remote.jobs) != 0 { t.Fatal("ACK not completed") }
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	remoteStepNow(a)
	if cancelCalls != 1 || len(a.remote.jobs) != 0 { t.Fatal("active disconnect did not notify controller") }
}
