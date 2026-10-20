// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"supivpn/internal/logging"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

type auditBuffer struct {
	mu sync.Mutex
	buf bytes.Buffer
}

func (b *auditBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *auditBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureAudit(t *testing.T, agents ...*agent) *auditBuffer {
	t.Helper()
	b := &auditBuffer{}
	logger := logging.New(b, "agent")
	for _, a := range agents { a.logger = logger }
	return b
}

func assertTunnelAudit(t *testing.T, logs *auditBuffer, event, username, group, address string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil { t.Fatal("audit output is not JSON lines") }
		if entry["event"] != event || entry["username"] != username { continue }
		if entry["cid"] != float64(7) || entry["component"] != "agent" { t.Fatal("connection audit metadata missing") }
		if group != "" && (entry["group_name"] != group || entry["address"] != address) { t.Fatal("wrong group or address") }
		return
	}
	t.Fatalf("missing %s audit event", event)
}

func TestAuditUsernameFromVerifiedSAML(t *testing.T) {
	signer, md := testIdP(t)
	for _, tc := range []struct { name, username string; signed, tampered bool }{
		{"valid", "test-user", true, false},
		{"escaped", "alice\"\nVPN forged\t\u202e", true, false},
		{"unicode", "\u0421\u0442\u0430\u043d\u0456\u0441\u043b\u0430\u0432", true, false},
		{"unsigned", "test-user", false, false},
		{"tampered", "test-user", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, commands := testApp(t, md)
			logs := captureAudit(t, a.agent)
			a.config.AllowedSubjects = []string{tc.username}
			assertion := assertionFor(a)
			assertion.Subject.NameID.Value = tc.username
			body := responseBody(t, a, signer, assertion, tc.signed, tc.tampered)
			res := submit(a, body, "test-browser")
			if !tc.signed || tc.tampered {
				if res.Code == http.StatusOK || a.connections[7].username != "" { t.Fatal("unverified username accepted") }
				a.handleEvent(clientEvent{kind:"DISCONNECT", cid:7})
				if strings.Contains(logs.String(), "\"username\":") { t.Fatal("unverified identity logged") }
				return
			}
			if res.Code != http.StatusOK || a.connections[7].username != tc.username { t.Fatal("verified username lost") }
			if cmd := <-commands; cmd != "client-auth-nt 7 2" { t.Fatal("audit data changed OpenVPN authorization") }
			a.handleEvent(clientEvent{kind:"ESTABLISHED", cid:7})
			a.handleEvent(clientEvent{kind:"DISCONNECT", cid:7})
			for _, event := range []string{"vpn.tunnel_established", "vpn.disconnected"} {
				assertTunnelAudit(t, logs, event, tc.username, "", "")
			}
			if strings.Count(logs.String(), "\n") != 3 { t.Fatal("username injected extra log lines") }
			if a.connections[7] != nil { t.Fatal("identity retained after disconnect") }
		})
	}
}

func TestRemoteAuditUsernameAndGroup(t *testing.T) {
	api := remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
		if op == "fetch" {
			if q.IncludeUsername == nil || !*q.IncludeUsername { t.Fatal("username capability not requested") }
			d := allowedRemoteDecision(coreGroup)
			d.Username = "alice"
			return d, nil
		}
		return nil, nil
	})
	a, commands := remoteFixture(t, api)
	logs := captureAudit(t, a)
	connectRemote(t, a, commands)
	remoteStepNow(a)
	if cmd := <-commands; cmd != "client-auth 7 2\nifconfig-push 10.203.0.2 255.255.255.0\nEND" { t.Fatal("audit data changed management commands") }
	a.handleEvent(clientEvent{kind:"ESTABLISHED", cid:7})
	a.handleEvent(clientEvent{kind:"REAUTH", cid:7, kid:3})
	<-commands
	a.handleEvent(clientEvent{kind:"DISCONNECT", cid:7})
	for _, event := range []string{"vpn.tunnel_established", "vpn.disconnected"} {
		assertTunnelAudit(t, logs, event, "alice", coreGroup, "10.203.0.2")
	}
	// Reuse of a CID must not inherit the previous user's identity.
	a.handleEvent(clientEvent{kind:"CONNECT", cid:7, kid:4, sso:"webauth"})
	if a.connections[7].username != "" { t.Fatal("CID reused previous username") }
}
