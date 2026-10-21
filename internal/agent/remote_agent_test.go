// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

type remoteAPIFunc func(context.Context, string, agentclient.Request) (*agentapi.Decision, error)

func (f remoteAPIFunc) Call(ctx context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
	return f(ctx, op, q)
}

type agentRoundTrip func(*http.Request) (*http.Response, error)

func (f agentRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func remoteFixture(t *testing.T, api agentclient.API) (*agent, chan string) {
	t.Helper()
	origin, _ := url.Parse("https://vpn.example.test:8443")
	a := newAgent(groupConfig(), origin)
	a.pools = newPoolAllocator(a.config)
	m, commands := fakeManagement(t)
	a.attach(m)
	a.remote = &remoteAgent{api: api, node: "runtime-node", generation: "g1", publicURL: "https://login.example.test/supivpn"}
	// Ordinary mailbox tests isolate heartbeat scheduling; lease tests override.
	a.remote.leaseUntil, a.remote.heartbeatDue = time.Now().Add(24*time.Hour), time.Now().Add(24*time.Hour)
	return a, commands
}
func remoteStepNow(a *agent) {
	a.mu.Lock()
	for _, j := range a.remote.jobs {
		j.due = time.Time{}
	}
	a.mu.Unlock()
	a.remoteStep(context.Background())
}
func allowedRemoteDecision(group string) *agentapi.Decision {
	return &agentapi.Decision{ID: "decision-1", NodeID: "runtime-node", Generation: "g1", CID: 7, KID: 2,
		GroupName: group, ExpiresAt: time.Now().Add(time.Minute), SessionExpiresAt: time.Now().Add(10 * time.Minute)}
}
func connectRemote(t *testing.T, a *agent, commands chan string) {
	t.Helper()
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth"})
	if len(commands) != 0 {
		t.Fatal("browser opened before registration")
	}
	remoteStepNow(a)
	select {
	case cmd := <-commands:
		if !strings.Contains(cmd, "WEB_AUTH:external:https://login.example.test/supivpn/login/") {
			t.Fatal("incorrect browser destination")
		}
	default:
		t.Fatal("browser request missing")
	}
}
func TestRemoteDecisionAndLostAcknowledgement(t *testing.T) {
	for _, group := range []string{coreGroup, devGroup} {
		t.Run(group, func(t *testing.T) {
			acks := 0
			api := remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
				switch op {
				case "register":
					if q.Generation != "g1" || *q.CID != 7 || *q.KID != 2 || len(q.Ticket) != 43 {
						t.Fatal("bad registration")
					}
				case "fetch":
					return allowedRemoteDecision(group), nil
				case "ack":
					acks++
					if q.DecisionID != "decision-1" || q.Outcome != "applied" {
						t.Fatal("bad ACK")
					}
					if acks == 1 {
						return nil, &agentclient.Error{Status: 503}
					}
				default:
					t.Fatal("unexpected operation", op)
				}
				return nil, nil
			})
			a, commands := remoteFixture(t, api)
			connectRemote(t, a, commands)
			remoteStepNow(a)
			address := "10.203.0.2"
			if group == devGroup {
				address = "10.203.0.65"
			}
			if cmd := <-commands; cmd != "client-auth 7 2\nifconfig-push "+address+" 255.255.255.0\nEND" {
				t.Fatal("wrong group IP command", cmd)
			}
			deadline := a.connections[7].expires
			remoteStepNow(a)
			remoteStepNow(a)
			remoteStepNow(a)
			if acks != 2 || len(commands) != 0 || len(a.remote.jobs) != 0 || a.connections[7].expires != deadline {
				t.Fatal("ACK retry repeated authorization or extended session")
			}
			a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3})
			if cmd := <-commands; cmd != "client-auth-nt 7 3" {
				t.Fatal(cmd)
			}
			a.now = func() time.Time { return deadline.Add(time.Second) }
			a.expire()
			if cmd := <-commands; cmd != "client-kill 7" {
				t.Fatal("expired remote session survived")
			}
			if len(a.pools.leases) != 1 {
				t.Fatal("lease reused before disconnect")
			}
			a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
			if len(a.pools.leases) != 0 {
				t.Fatal("lease leaked")
			}
		})
	}
}

func TestRemoteRefusesInvalidDecisions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*agentapi.Decision)
	}{
		{"node", func(d *agentapi.Decision) { d.NodeID = "other" }},
		{"generation", func(d *agentapi.Decision) { d.Generation = "old" }},
		{"cid", func(d *agentapi.Decision) { d.CID++ }},
		{"kid", func(d *agentapi.Decision) { d.KID++ }},
		{"expired", func(d *agentapi.Decision) { d.ExpiresAt = time.Now().Add(-time.Second) }},
		{"session-expired", func(d *agentapi.Decision) { d.SessionExpiresAt = time.Now().Add(-time.Second) }},
		{"session-too-long", func(d *agentapi.Decision) { d.SessionExpiresAt = time.Now().Add(time.Hour) }},
		{"missing-group", func(d *agentapi.Decision) { d.GroupName = "" }},
		{"unknown-group", func(d *agentapi.Decision) { d.GroupName = "other-vpn" }},
		{"denied", func(d *agentapi.Decision) { d.GroupName, d.DenialReason = "", "no_vpn_group" }},
		{"denial-with-group", func(d *agentapi.Decision) { d.DenialReason = "no_vpn_group" }},
		{"bad-denial", func(d *agentapi.Decision) { d.GroupName, d.DenialReason = "", "anything" }},
		{"missing-id", func(d *agentapi.Decision) { d.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := allowedRemoteDecision(coreGroup)
			tc.mutate(d)
			api := remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
				if op == "fetch" {
					return d, nil
				}
				return nil, nil
			})
			a, commands := remoteFixture(t, api)
			connectRemote(t, a, commands)
			remoteStepNow(a)
			if !strings.HasPrefix(<-commands, "client-deny 7 2 ") || a.connections[7].active || len(a.pools.leases) != 0 {
				t.Fatal("invalid decision authorized")
			}
		})
	}
}
func TestDisconnectDoesNotWaitForControllerAndLateReplyCannotAuthorize(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	cancels := 0
	api := remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
		if op == "fetch" {
			close(entered)
			<-release
			return allowedRemoteDecision(coreGroup), nil
		}
		if op == "cancel" {
			cancels++
		}
		return nil, nil
	})
	a, commands := remoteFixture(t, api)
	connectRemote(t, a, commands)
	finished := make(chan struct{})
	go func() { remoteStepNow(a); close(finished) }()
	<-entered
	disconnected := make(chan struct{})
	go func() { a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7}); close(disconnected) }()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("HTTP blocked disconnect")
	}
	// Replace the CID before the old response arrives: pointer identity fences it.
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth"})
	close(release)
	<-finished
	if len(commands) != 0 || a.connections[7].active || len(a.pools.leases) != 0 {
		t.Fatal("late decision reached replacement CID")
	}
	remoteStepNow(a)
	remoteStepNow(a)
	if cancels != 1 {
		t.Fatal("old registration not cancelled")
	}
}
func TestRemoteUnavailableAndGenerationConflict(t *testing.T) {
	status := 503
	a, commands := remoteFixture(t, remoteAPIFunc(func(context.Context, string, agentclient.Request) (*agentapi.Decision, error) {
		return nil, &agentclient.Error{Status: status}
	}))
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth"})
	remoteStepNow(a)
	if len(commands) != 0 || len(a.remote.jobs) != 1 {
		t.Fatal("outage authorized or discarded pending request")
	}
	status = 409
	remoteStepNow(a)
	select {
	case <-a.management.done:
	default:
		t.Fatal("generation conflict left OpenVPN running")
	}
}
func TestRemoteDoesNotServeLocalSAML(t *testing.T) {
	a, _ := remoteFixture(t, nil)
	for _, path := range []string{"/saml/metadata", "/saml/acs", "/login/ticket"} {
		r := httptest.NewRequest("GET", a.origin.String()+path, nil)
		w := httptest.NewRecorder()
		a.remoteHealth().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("local SAML fallback exposed")
		}
	}
}
