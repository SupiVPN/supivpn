// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/tracecontext"
)

func traceRows(t *testing.T, b *auditBuffer) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			t.Fatal("invalid trace JSON")
		}
		rows = append(rows, row)
	}
	return rows
}

func TestTraceSurvivesRetryRekeyDisconnectAndCIDReuse(t *testing.T) {
	var id string
	acks := 0
	ops := map[string]int{}
	api := remoteAPIFunc(func(ctx context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
		got := tracecontext.ID(ctx)
		if !tracecontext.ValidID(got) || id != "" && got != id {
			t.Fatal("mailbox trace lost")
		}
		id = got
		ops[op]++
		if op == "fetch" {
			return allowedRemoteDecision(coreGroup), nil
		}
		if op == "ack" {
			acks++
			if acks == 1 {
				return nil, &agentclient.Error{Status: 503}
			}
		}
		return nil, nil
	})
	a, commands := remoteFixture(t, api)
	logs := captureAudit(t, a)
	connectRemote(t, a, commands)
	remoteStepNow(a)
	<-commands
	remoteStepNow(a) // Lost ACK response.
	remoteStepNow(a) // Retry must retain the trace and original binding.
	a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
	a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 9})
	if <-commands != "client-auth-nt 7 9" {
		t.Fatal("rekey behavior changed")
	}
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
	remoteStepNow(a)
	seen := map[string]bool{}
	for _, row := range traceRows(t, logs) {
		if row["trace_id"] != id {
			t.Fatal("session event lost trace")
		}
		seen[row["event"].(string)] = true
		if row["event"] == "vpn.tls_reauthenticated" && row["kid"] != float64(9) {
			t.Fatal("rekey log reported old key ID")
		}
	}
	for _, event := range []string{"vpn.connection_requested", "vpn.browser_auth_requested", "vpn.authorization_applied", "controller.request_retry", "vpn.tunnel_established", "vpn.tls_reauthenticated", "vpn.disconnected"} {
		if !seen[event] {
			t.Fatal("missing traced event", event)
		}
	}
	if ops["register"] != 1 || ops["fetch"] != 1 || ops["ack"] != 2 || ops["cancel"] != 1 {
		t.Fatal("trace changed mailbox operations")
	}
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth"})
	rows := traceRows(t, logs)
	if rows[len(rows)-1]["trace_id"] == id {
		t.Fatal("reused CID inherited old trace")
	}
}
