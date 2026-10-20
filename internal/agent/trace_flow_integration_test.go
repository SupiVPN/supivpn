// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/tracecontext"
)

func TestTraceFullFlowAcrossReplicas(t *testing.T) {
	groups := []string{coreGroup, devGroup}
	f := newGroupLifecycleFixture(t, groups, groups, groups)
	logs := captureAudit(t, f.agents[:]...)
	f.publicLogger = logging.New(logs, "public")
	for _, a := range f.agents {
		transport := a.remote.api
		a.remote.api = remoteAPIFunc(func(ctx context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
			ctx = logging.WithLogger(logging.WithRequestID(ctx, "api-"+op), logging.New(logs, "agent_api"))
			return transport.Call(ctx, op, q)
		})
	}
	// Overlapping flows reuse CID/KID on different nodes. Start on one controller
	// replica, then finish through a fresh controller using the same database.
	first := f.begin(t, 0, 7, "trace-alice", coreGroup)
	second := f.begin(t, 1, 7, "trace-bob", devGroup)
	f.setPolicy(t, groups)
	ids := map[string]bool{}
	for _, login := range []groupLifecycleLogin{second, first} {
		a := f.agents[login.node]
		ticket := a.connections[7].ticket
		id := tracecontext.ForLogin(ticket)
		if !tracecontext.ValidID(id) || ids[id] {
			t.Fatal("parallel sessions share trace")
		}
		ids[id] = true
		login.request.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
		f.callback(t, login, http.StatusAccepted)
		group := coreGroup
		if login.node == 1 {
			group = devGroup
		}
		f.deliver(t, login, group)
		a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
		a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 4})
		if lifecycleCommand(t, f.commands[login.node]) != "client-auth-nt 7 4" {
			t.Fatal("rekey binding changed")
		}
		f.disconnect(t, login)
		hash := sha256.Sum256([]byte(ticket))
		if strings.Contains(logs.String(), ticket) || strings.Contains(logs.String(), hex.EncodeToString(hash[:])) {
			t.Fatal("correlation disclosed login material")
		}
		seen := map[string]bool{}
		components := map[string]bool{}
		for _, row := range traceRows(t, logs) {
			if row["trace_id"] != id {
				continue
			}
			seen[row["event"].(string)] = true
			components[row["component"].(string)] = true
		}
		for _, event := range []string{"vpn.connection_requested", "agent.login_registered", "vpn.browser_auth_requested", "saml.login_started", "saml.authorization_decided", "agent.decision_delivered", "vpn.authorization_applied", "agent.decision_acknowledged", "vpn.tunnel_established", "vpn.tls_reauthenticated", "vpn.disconnected", "agent.connection_cancelled"} {
			if !seen[event] {
				t.Fatal("full flow lost event", event)
			}
		}
		for _, component := range []string{"agent", "agent_api", "public"} {
			if !components[component] {
				t.Fatal("missing component correlation", component)
			}
		}
	}
	// A different authenticated node cannot make an ACK appear in this trace.
	before := logs.String()
	ctx := logging.WithLogger(context.Background(), logging.New(logs, "agent_api"))
	if err := f.stores[0].Acknowledge(ctx, postgres.Agent{NodeID: "foreign-node", Generation: "g1"}, "foreign-decision", postgres.Applied); err == nil {
		t.Fatal("foreign ACK accepted")
	}
	if logs.String() != before {
		t.Fatal("unauthorized operation emitted a bound success")
	}
	denied := f.begin(t, 0, 8, "trace-denied", unrelatedGroup)
	id := tracecontext.ForLogin(f.agents[0].connections[8].ticket)
	f.callback(t, denied, http.StatusForbidden)
	f.deliver(t, denied, "")
	f.disconnect(t, denied)
	found := map[string]bool{}
	for _, row := range traceRows(t, logs) {
		if row["trace_id"] == id {
			found[row["event"].(string)] = true
		}
	}
	if !found["saml.authorization_decided"] || !found["vpn.authorization_denied"] || !found["agent.connection_cancelled"] || found["vpn.tunnel_established"] {
		t.Fatal("denied flow correlation incorrect")
	}
}
