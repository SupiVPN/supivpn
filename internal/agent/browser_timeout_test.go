// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
)

func TestUnansweredBrowserStopsReconnect(t *testing.T) {
	for _, mode := range []string{"local", "expiry-first", "worker-first", "late-register", "late-fetch", "late-fetch-after-timer", "late-fetch-refused"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			deadline := now.Add(30 * time.Second)
			cancels := 0
			var a *agent
			var commands chan string
			a, commands = remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
				if op == "cancel" {
					cancels++
				}
				if op == "register" && mode == "late-register" {
					now = deadline
				}
				if op == "fetch" && strings.HasPrefix(mode, "late-fetch") {
					now = deadline
					if mode == "late-fetch-after-timer" {
						a.expire()
					}
					if mode == "late-fetch-refused" {
						return nil, &agentclient.Error{Status: 410}
					}
					return allowedRemoteDecision(coreGroup), nil
				}
				return nil, nil
			}))
			if mode == "local" {
				a.remote = nil
			}
			a.now = func() time.Time { return now }
			a.config.PendingSeconds = 30
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth"})
			if a.remote != nil {
				remoteStepNow(a)
			}
			c := a.connections[7]
			if !c.expires.Equal(deadline) {
				t.Fatal("authentication deadline was extended")
			}
			if mode != "late-register" {
				if cmd := <-commands; !strings.HasPrefix(cmd, "client-pending-auth 7 2 ") || !strings.HasSuffix(cmd, " 40") {
					t.Fatal("browser control channel lacks bounded shutdown headroom")
				}
				now = deadline.Add(-time.Millisecond)
				a.expire()
				if len(commands) != 0 {
					t.Fatal("authentication ended early")
				}
				if strings.HasPrefix(mode, "late-fetch") {
					remoteStepNow(a)
				} else {
					now = deadline
					if mode == "worker-first" {
						remoteStepNow(a)
					} else {
						a.expire()
					}
				}
			}
			select {
			case cmd := <-commands:
				if cmd != `client-kill 7 "HALT,Browser authentication timed out; reconnect manually"` {
					t.Fatal("unanswered browser login did not stop reconnect")
				}
			default:
				t.Fatal("expired browser login was not stopped")
			}
			a.expire()
			if a.remote != nil {
				remoteStepNow(a)
			}
			if c.active || !c.closing || a.connections[7] != c || a.tickets[c.ticket] != nil ||
				len(a.pools.leases) != 0 || len(commands) != 0 || cancels != 0 || !a.readyLocked() {
				t.Fatal("timeout authorized, repeated shutdown, or cancelled before disconnect")
			}
			a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
			if a.remote != nil {
				remoteStepNow(a)
				if cancels != 1 {
					t.Fatal("confirmed disconnect was not cancelled")
				}
			}
			if len(a.connections) != 0 {
				t.Fatal("disconnected pending connection survived")
			}
			// A new user-initiated connection must still be able to sign in.
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 8, kid: 2, sso: "webauth"})
			if a.remote != nil {
				remoteStepNow(a)
			}
			if cmd := <-commands; !strings.HasPrefix(cmd, "client-pending-auth 8 2 ") {
				t.Fatal("manual retry could not sign in")
			}
		})
	}
}

func TestBrowserTimeoutDoesNotExtendAuthorization(t *testing.T) {
	for _, lifetime := range []time.Duration{30 * time.Second, 180 * time.Second, 1500 * time.Millisecond} {
		t.Run(lifetime.String(), func(t *testing.T) {
			a, commands := remoteFixture(t, nil)
			now := time.Now()
			a.now = func() time.Time { return now }
			c := &connection{cid: 7, kid: 2, ticket: "synthetic-ticket", requestID: "synthetic-request", expires: now.Add(lifetime)}
			a.connections[7], a.tickets[c.ticket] = c, c
			pending := pendingSnapshot(c)
			deadline := c.expires
			if err := a.requestBrowserLocked(c, a.origin.String()); err != nil {
				t.Fatal(err)
			}
			if cmd := <-commands; !strings.HasSuffix(cmd, fmt.Sprintf(" %d", int(lifetime.Seconds())+10)) {
				t.Fatal("control timeout must have only ten seconds of headroom")
			}
			now = deadline
			if !c.expires.Equal(deadline) || a.pendingConnectionLocked(c) || a.requestBrowserLocked(c, a.origin.String()) == nil || len(commands) != 0 {
				t.Fatal("transport headroom extended browser authorization")
			}
			decision := controller.Authorization{Username: "synthetic-user", SubjectHash: sha256.Sum256([]byte("synthetic-owner")),
				MaxConnections: 1, GroupName: coreGroup, NotBefore: now.Add(-time.Minute),
				NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(5 * time.Minute)}
			if err := a.Complete(context.Background(), pending, decision); err != controller.ErrLoginExpired || c.active || len(a.pools.leases) != 0 {
				t.Fatal("late authorization used transport headroom")
			}
			// The same decision is otherwise valid, so only pending expiry rejects it.
			now = deadline.Add(-time.Nanosecond)
			if err := a.Complete(context.Background(), pending, decision); err != nil || !c.active {
				t.Fatal("control authorization was invalid")
			}
		})
	}
}
