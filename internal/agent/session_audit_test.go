// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
)

func auditRow(t *testing.T, logs *auditBuffer, event string, cid uint64) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			t.Fatal("invalid audit JSON")
		}
		if row["event"] == event && row["cid"] == float64(cid) {
			return row
		}
	}
	t.Fatal("missing audit event", event)
	return nil
}

func envEvent(t *testing.T, header, env string) clientEvent {
	t.Helper()
	block := ">CLIENT:" + header + "\n"
	for _, line := range strings.Split(env, "\n") {
		block += ">CLIENT:ENV," + line + "\n"
	}
	events := managementPeerEvents(t, block+">CLIENT:ENV,END\n")
	if len(events) != 1 {
		t.Fatal("metadata changed event delivery")
	}
	return events[0]
}

func TestSessionEnvironmentValidation(t *testing.T) {
	valid := "IV_VER=3.11.0 (release)\nIV_PLAT=android"
	e := envEvent(t, "CONNECT,7,2", valid)
	if e.client.version != "3.11.0 (release)" || e.client.platform != "android" {
		t.Fatal("client diagnostics lost")
	}
	for _, bad := range []string{"", "v\tforged", "v\rforged", "v\u202eforged", " v1", strings.Repeat("a", 129)} {
		e = envEvent(t, "CONNECT,7,2", "IV_VER="+bad+"\nIV_PLAT="+bad)
		if e.client != (clientInfo{}) {
			t.Fatal("invalid diagnostic retained")
		}
	}
	for _, block := range []string{valid + "\nIV_VER=other\nIV_PLAT=win", valid + "\nIV_VER=other\nIV_VER=third\nIV_PLAT=win\nIV_PLAT=linux"} {
		if envEvent(t, "CONNECT,7,2", block).client != (clientInfo{}) {
			t.Fatal("duplicate diagnostic retained")
		}
	}
	for _, header := range []string{"REAUTH,7,3", "ESTABLISHED,7", "DISCONNECT,7"} {
		if envEvent(t, header, valid).client != (clientInfo{}) {
			t.Fatal("later event replaced initial client diagnostics")
		}
	}
	for _, field := range []string{"time_duration", "bytes_received", "bytes_sent"} {
		for _, value := range []string{"0", "123", "18446744073709551615", "", "-1", "+1", " 1", "1.5", "18446744073709551616", "1\tforged", "2\n" + field + "=3"} {
			e = envEvent(t, "DISCONNECT,7", field+"="+value)
			var counter auditCounter
			switch field {
			case "time_duration":
				counter = e.metrics.duration
			case "bytes_received":
				counter = e.metrics.received
			case "bytes_sent":
				counter = e.metrics.sent
			}
			wantValid := value == "0" || value == "123" || value == "18446744073709551615"
			if !counter.seen || counter.invalid == wantValid {
				t.Fatal("invalid counter validation", field)
			}
		}
	}
	for _, header := range []string{"CONNECT,7,2", "REAUTH,7,3", "ESTABLISHED,7"} {
		if envEvent(t, header, "time_duration=5\nbytes_received=123\nbytes_sent=456").metrics != (disconnectMetrics{}) {
			t.Fatal("non-final counters accepted")
		}
	}
	e = envEvent(t, "DISCONNECT,7", "UV_bytes_received=999\nIV_BYTES_SENT=999\nsignal=forged\ndisconnect_reason=operator_requested")
	if e.metrics != (disconnectMetrics{}) {
		t.Fatal("unselected environment retained")
	}
	events := managementPeerEvents(t, ">CLIENT:CONNECT,7,2\n>CLIENT:ENV,IV_VER=2.7.8\n>CLIENT:ENV,END\n>CLIENT:DISCONNECT,7\n>CLIENT:ENV,bytes_sent=99\n>CLIENT:ENV,END\n>CLIENT:CONNECT,8,2\n>CLIENT:ENV,END\n>CLIENT:DISCONNECT,8\n>CLIENT:ENV,END\n")
	if len(events) != 4 || events[2].client != (clientInfo{}) || events[3].metrics != (disconnectMetrics{}) {
		t.Fatal("metadata crossed environment blocks")
	}
	partial := managementPeerEvents(t, ">CLIENT:CONNECT,7,2\n>CLIENT:ENV,IV_VER=2.7.8\n>CLIENT:CONNECT,8,2\n>CLIENT:ENV,END\n")
	if len(partial) != 1 || partial[0].client != (clientInfo{}) {
		t.Fatal("interrupted block retained metadata")
	}
}

func TestSessionAuditLifecycle(t *testing.T) {
	for _, mode := range []string{"disconnect", "status", "pending", "invalid", "zero", "missing-start", "backwards-clock"} {
		t.Run(mode, func(t *testing.T) {
			origin, _ := url.Parse("https://vpn.example.test")
			a := newAgent(groupConfig(), origin)
			a.attach(statusManagement(t, func(string) string { return "SUCCESS: acknowledged\n" }))
			logs := captureAudit(t, a)
			now := time.Now()
			a.now = func() time.Time { return now }
			a.handleEvent(envEvent(t, "CONNECT,7,2", "IV_SSO=webauth\nIV_VER=2.7.8\nIV_PLAT=linux"))
			c := a.connections[7]
			if mode != "pending" {
				c.active, c.username, c.expires = true, "verified-user", now.Add(time.Hour)
				if mode == "missing-start" {
					c.requestedAt = time.Time{}
				}
				if mode == "backwards-clock" {
					now = now.Add(-time.Second)
				} else {
					now = now.Add(2345 * time.Millisecond)
				}
				a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
				row := auditRow(t, logs, "vpn.tunnel_established", 7)
				if row["client_version"] != "2.7.8" || row["client_platform"] != "linux" {
					t.Fatal("missing client diagnostics")
				}
				if mode == "missing-start" || mode == "backwards-clock" {
					if _, ok := row["establishment_ms"]; ok {
						t.Fatal("unknown/negative establishment fabricated")
					}
				} else if row["establishment_ms"] != float64(2345) {
					t.Fatal("incorrect establishment time")
				}
				if _, ok := row["bytes_received"]; ok {
					t.Fatal("non-final counter logged")
				}
				// Rekey must preserve the original labels and establishment start.
				a.handleEvent(envEvent(t, "REAUTH,7,3", "IV_VER=forged\nIV_PLAT=forged"))
				if c.client.version != "2.7.8" {
					t.Fatal("reauth replaced diagnostics")
				}
			}
			disconnect := envEvent(t, "DISCONNECT,7", "time_duration=8\nbytes_received=123\nbytes_sent=456\ndisconnect_reason=forged\nsignal=ping-restart")
			source := "management_event"
			if mode == "status" {
				disconnect = clientEvent{kind: "STATUS", clients: map[uint64]struct{}{}}
				source = "status_snapshot"
			}
			if mode == "invalid" {
				disconnect = envEvent(t, "DISCONNECT,7", "time_duration=-1\nbytes_received=123\nbytes_received=124\nbytes_sent=overflow")
			}
			if mode == "zero" {
				disconnect = envEvent(t, "DISCONNECT,7", "time_duration=0\nbytes_received=0\nbytes_sent=0")
			}
			a.handleEvent(disconnect)
			row := auditRow(t, logs, "vpn.disconnected", 7)
			if row["disconnect_source"] != source {
				t.Fatal("incorrect disconnect evidence")
			}
			if _, ok := row["disconnect_reason"]; ok {
				t.Fatal("unknown reason fabricated")
			}
			for key, want := range map[string]float64{"duration_seconds": 8, "bytes_received": 123, "bytes_sent": 456} {
				if mode == "status" || mode == "pending" || mode == "invalid" {
					if _, ok := row[key]; ok {
						t.Fatal("missing/final counter fabricated", key)
					}
				} else {
					if mode == "zero" {
						want = 0
					}
					if row[key] != want {
						t.Fatal("incorrect final counter", key)
					}
				}
			}
			for _, key := range []string{"client_version", "client_platform", "establishment_ms"} {
				if _, ok := row[key]; ok {
					t.Fatal("establishment metadata on disconnect")
				}
			}
			if a.connections[7] != nil {
				t.Fatal("audit retained disconnected CID")
			}
			logs.mu.Lock()
			logs.buf.Reset()
			logs.mu.Unlock()
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 4, sso: "webauth"})
			c = a.connections[7]
			c.active = true
			a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
			row = auditRow(t, logs, "vpn.tunnel_established", 7)
			if _, ok := row["client_version"]; ok {
				t.Fatal("CID reused old diagnostics")
			}
			a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
			row = auditRow(t, logs, "vpn.disconnected", 7)
			if _, ok := row["bytes_sent"]; ok {
				t.Fatal("CID reused old counters")
			}
		})
	}
}

func TestSessionAuditKnownReasons(t *testing.T) {
	for _, mode := range []string{"expiry", "reauth-expiry", "pending-expiry", "operator", "denied", "remote-refusal"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := operatorFixture(t)
			logs := captureAudit(t, a)
			c := a.connections[1]
			want := "session_expired"
			switch mode {
			case "expiry":
				c.expires = time.Now().Add(-time.Second)
				a.expire()
			case "reauth-expiry":
				c.expires = time.Now().Add(-time.Second)
				a.handleEvent(clientEvent{kind: "REAUTH", cid: 1, kid: 3})
			case "pending-expiry":
				c.active = false
				c.expires = time.Now().Add(-time.Second)
				a.expire()
				want = "pending_auth_expired"
			case "operator":
				if _, err := a.userSessions(context.Background(), "https://idp.example.test", userSessionsRequest{Operation: "drop", Username: "alice"}); err != nil {
					t.Fatal(err)
				}
				want = "operator_requested"
			case "denied":
				c.active = false
				if a.applyAuthorizationLocked(c, controller.Authorization{DenialReason: "no_vpn_group"}) == nil {
					t.Fatal("denial accepted")
				}
				want = "no_vpn_group"
			case "remote-refusal":
				c.active = false
				a.refuseRemoteLocked(c)
				want = "controller_refused"
			}
			// A later expiry attempt must not overwrite an operator's first decision.
			a.closeClientLocked(c, "pending_auth_expired")
			if c.disconnectReason != want {
				t.Fatal("incorrect remembered reason", c.disconnectReason, want)
			}
			a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 1})
			row := auditRow(t, logs, "vpn.disconnected", 1)
			if row["disconnect_reason"] != want || row["disconnect_source"] != "management_event" {
				t.Fatal("reason or evidence lost")
			}
		})
	}
}

func TestSessionAuditMissingDisconnectKeepsReason(t *testing.T) {
	a, _ := operatorFixture(t)
	logs := captureAudit(t, a)
	if _, err := a.userSessions(context.Background(), "https://idp.example.test", userSessionsRequest{Operation: "drop", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	a.handleEvent(clientEvent{kind: "STATUS", clients: map[uint64]struct{}{2: {}, 3: {}, 4: {}}})
	row := auditRow(t, logs, "vpn.disconnected", 1)
	if row["disconnect_reason"] != "operator_requested" || row["disconnect_source"] != "status_snapshot" {
		t.Fatal("status cleanup lost known reason")
	}
	if _, ok := row["duration_seconds"]; ok {
		t.Fatal("status fabricated duration")
	}
	// A later event for the removed CID must not recreate counters/identity.
	a.handleEvent(envEvent(t, "DISCONNECT,1", "bytes_sent=999"))
	if strings.Count(logs.String(), "\"bytes_sent\"") != 0 {
		t.Fatal("late unknown CID acquired counters")
	}
}
