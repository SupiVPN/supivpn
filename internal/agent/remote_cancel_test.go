// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

func TestConfirmedDisconnectSurvivesControllerUpdate(t *testing.T) {
	for _, source := range []string{"DISCONNECT", "STATUS"} {
		for _, status := range []int{0, 429, 502, 503} {
			t.Run(fmt.Sprintf("%s/status-%d", source, status), func(t *testing.T) {
				start := time.Now()
				now := start
				var calls, heartbeats int
				var cancelled bool
				a, commands := remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
					switch op {
					case "fetch":
						return allowedRemoteDecision(coreGroup), nil
					case "heartbeat":
						heartbeats++
					case "cancel":
						calls++
						if q.Generation != "g1" || q.CID == nil || *q.CID != 7 || q.KID == nil || *q.KID != 2 {
							t.Fatal("cancellation lost its original connection binding")
						}
						if now.Before(start.Add(90 * time.Second)) {
							return nil, &agentclient.Error{Status: status}
						}
						cancelled = true
					}
					return nil, nil
				}))
				a.now = func() time.Time { return now }
				a.remote.leaseUntil, a.remote.heartbeatDue = start.Add(40*time.Second), start.Add(15*time.Second)
				connectRemote(t, a, commands)
				remoteStepNow(a)
				<-commands
				remoteStepNow(a)
				// A second, live tunnel must not be cancelled with the disconnected CID.
				a.connections[8] = &connection{cid: 8, kid: 1, active: true, expires: start.Add(time.Hour)}
				a.handleEvent(clientEvent{kind: source, cid: 7, clients: map[uint64]struct{}{8: {}}})
				for step := 0; step <= 480; step++ {
					now = start.Add(time.Duration(step) * 250 * time.Millisecond)
					a.remoteStep(context.Background())
					if !a.readyLocked() {
						t.Fatalf("confirmed cancellation stopped a healthy listener after %v", now.Sub(start))
					}
				}
				if !cancelled || len(a.remote.jobs) != 0 || a.connections[8] == nil || len(commands) != 0 {
					t.Fatal("cancellation did not recover independently of the live tunnel")
				}
				if calls < 2 || calls > 12 || heartbeats != 8 {
					t.Fatalf("unexpected retry/heartbeat budget: %d/%d", calls, heartbeats)
				}
			})
		}
	}
}

// A live tunnel with an uncertain ACK is different from a proven disconnect.
// Its delivery deadline and the node lease must continue to fail closed.
func TestCancellationRetryDoesNotRelaxLiveSessionDeadlines(t *testing.T) {
	for _, phase := range []string{"ack", "cancel", "unconfirmed-cancel"} {
		t.Run(phase, func(t *testing.T) {
			start := time.Now()
			a, _ := remoteFixture(t, remoteAPIFunc(func(context.Context, string, agentclient.Request) (*agentapi.Decision, error) {
				return nil, &agentclient.Error{Status: 503}
			}))
			c := &connection{cid: 7, kid: 2, active: true, expires: start.Add(time.Hour)}
			a.connections[7] = c
			a.remote.jobs = []*remoteJob{{conn: c, phase: "ack", outcome: "applied", deadline: start.Add(time.Second)}}
			if phase == "unconfirmed-cancel" {
				a.remote.jobs[0].phase = "cancel"
			}
			if phase == "cancel" {
				a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
				a.remote.leaseUntil = start.Add(time.Second)
			}
			a.now = func() time.Time { return start.Add(time.Second) }
			a.remoteStep(context.Background())
			if a.readyLocked() {
				t.Fatal("expired live ACK or lease did not stop the listener")
			}
		})
	}
}

func TestConfirmedCancellationQueueRemainsBounded(t *testing.T) {
	a, commands := remoteFixture(t, nil)
	for cid := uint64(1); cid <= maxRemoteJobs; cid++ {
		a.connections[cid] = &connection{cid: cid, kid: 1, active: true}
		a.handleEvent(clientEvent{kind: "DISCONNECT", cid: cid})
	}
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 100, kid: 1, sso: "webauth"})
	if !a.readyLocked() || len(a.remote.jobs) != maxRemoteJobs || len(a.connections) != 0 || len(commands) != 1 {
		t.Fatal("full cancellation queue admitted more work or disrupted the listener")
	}
	// An existing connection that cannot fit its cancellation still fails closed.
	a.connections[101] = &connection{cid: 101, kid: 1, active: true}
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 101})
	if a.readyLocked() || len(a.remote.jobs) != maxRemoteJobs {
		t.Fatal("cancellation overflow bypassed the safety limit")
	}
}
