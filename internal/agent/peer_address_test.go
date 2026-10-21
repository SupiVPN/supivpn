// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func managementPeerEvents(t *testing.T, blocks ...string) []clientEvent {
	t.Helper()
	client, server := net.Pipe()
	m := newManagement(client)
	t.Cleanup(func() { m.close(); server.Close() })
	go func() {
		defer server.Close()
		for _, block := range blocks {
			if _, err := fmt.Fprint(server, block); err != nil {
				return
			}
		}
	}()
	var events []clientEvent
	for {
		select {
		case e, ok := <-m.events:
			if !ok {
				return events
			}
			events = append(events, e)
		case <-time.After(time.Second):
			t.Fatal("management peer events timed out")
		}
	}
}

func TestManagementPeerAddress(t *testing.T) {
	for _, kind := range []string{"CONNECT", "REAUTH", "ESTABLISHED", "DISCONNECT"} {
		prefix := "trusted"
		header := ">CLIENT:" + kind + ",7"
		if kind == "CONNECT" || kind == "REAUTH" {
			prefix = "untrusted"
			header += ",2"
		}
		for _, tc := range []struct{ name, env, want string }{
			{"ipv4", "_ip=198.51.100.24\n_port=54321", "198.51.100.24:54321"},
			{"ipv6", "_ip6=2001:db8::24\n_port=65535", "[2001:db8::24]:65535"},
			{"mapped-ipv4", "_ip6=::ffff:198.51.100.24\n_port=1", "198.51.100.24:1"},
			{"port-first", "_port=54321\n_ip=198.51.100.24", "198.51.100.24:54321"},
			{"missing-ip", "_port=54321", ""},
			{"missing-port", "_ip=198.51.100.24", ""},
			{"zero-port", "_ip=198.51.100.24\n_port=0", ""},
			{"overflow-port", "_ip=198.51.100.24\n_port=65536", ""},
			{"negative-port", "_ip=198.51.100.24\n_port=-1", ""},
			{"port-text", "_ip=198.51.100.24\n_port=443 forged", ""},
			{"hostname", "_ip=example.test\n_port=443", ""},
			{"zone", "_ip6=fe80::1%eth0\n_port=443", ""},
			{"wrong-family", "_ip=2001:db8::24\n_port=443", ""},
			{"brackets", "_ip6=[2001:db8::24]\n_port=443", ""},
			{"injection", "_ip=198.51.100.24\tforged\n_port=443", ""},
			{"duplicate-ip", "_ip=198.51.100.24\n_ip=198.51.100.25\n_port=443", ""},
			{"duplicate-family", "_ip=198.51.100.24\n_ip6=2001:db8::24\n_port=443", ""},
			{"duplicate-port", "_ip=198.51.100.24\n_port=443\n_port=444", ""},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				block := header + "\n"
				for _, env := range strings.Split(tc.env, "\n") {
					block += ">CLIENT:ENV," + prefix + env + "\n"
				}
				events := managementPeerEvents(t, block+">CLIENT:ENV,IV_SSO=webauth\n>CLIENT:ENV,END\n")
				if len(events) != 1 || events[0].kind != kind {
					t.Fatal("peer metadata changed event handling")
				}
				if tc.want == "" {
					if events[0].peer.IsValid() {
						t.Fatal("invalid peer metadata retained")
					}
					return
				}
				if events[0].peer != netip.MustParseAddrPort(tc.want) {
					t.Fatal("incorrect peer endpoint")
				}
			})
		}
	}
}

func TestManagementPeerMetadataDoesNotCrossEvents(t *testing.T) {
	events := managementPeerEvents(t,
		">CLIENT:CONNECT,7,2\n>CLIENT:ENV,untrusted_ip=198.51.100.24\n>CLIENT:ENV,untrusted_port=54321\n>CLIENT:ENV,END\n",
		">CLIENT:CONNECT,8,2\n>CLIENT:ENV,IV_PEER_IP=198.51.100.99\n>CLIENT:ENV,UV_PEER_PORT=9999\n>CLIENT:ENV,username=forged\n>CLIENT:ENV,password=synthetic\n>CLIENT:ENV,trusted_ip=198.51.100.99\n>CLIENT:ENV,trusted_port=9999\n>CLIENT:ENV,END\n",
		">CLIENT:ESTABLISHED,7\n>CLIENT:ENV,untrusted_ip=198.51.100.99\n>CLIENT:ENV,untrusted_port=9999\n>CLIENT:ENV,END\n")
	if len(events) != 3 || !events[0].peer.IsValid() || events[1].peer.IsValid() || events[2].peer.IsValid() {
		t.Fatal("unrelated fields or previous event supplied peer metadata")
	}
	// An interrupted environment block must not supply half of a later endpoint.
	events = managementPeerEvents(t, ">CLIENT:CONNECT,7,2\n>CLIENT:ENV,untrusted_ip=198.51.100.24\n>CLIENT:CONNECT,8,2\n>CLIENT:ENV,untrusted_port=54321\n>CLIENT:ENV,END\n")
	if len(events) != 1 || events[0].cid != 8 || events[0].peer.IsValid() {
		t.Fatal("partial endpoint crossed events")
	}
}

func assertPeerAudit(t *testing.T, logs *auditBuffer, event string, cid uint64, ip string, port uint16) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal("invalid audit JSON")
		}
		if row["event"] != event || row["cid"] != float64(cid) {
			continue
		}
		if ip == "" {
			if _, ok := row["peer_ip"]; ok {
				t.Fatal("unexpected peer IP")
			}
			if _, ok := row["peer_port"]; ok {
				t.Fatal("unexpected peer port")
			}
		} else if row["peer_ip"] != ip || row["peer_port"] != float64(port) {
			t.Fatal("incorrect peer audit endpoint")
		}
		return
	}
	t.Fatal("missing peer audit event", event)
}

func TestPeerAddressAuditLifecycle(t *testing.T) {
	for _, mode := range []string{"direct", "ipv6", "nlb-source", "established-update", "reauth-update", "disconnect-update", "reconciled", "missing", "pending"} {
		t.Run(mode, func(t *testing.T) {
			origin, _ := url.Parse("https://vpn.example.test")
			a := newAgent(groupConfig(), origin)
			a.attach(statusManagement(t, func(string) string { return "SUCCESS: accepted\n" }))
			logs := captureAudit(t, a)
			peer := netip.MustParseAddrPort("198.51.100.24:54321")
			switch mode {
			case "ipv6":
				peer = netip.MustParseAddrPort("[2001:db8::24]:54321")
			case "nlb-source":
				peer = netip.MustParseAddrPort("10.0.0.24:54321")
			case "missing":
				peer = netip.AddrPort{}
			}
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 2, sso: "webauth", peer: peer})
			c := a.connections[7]
			if c == nil {
				t.Fatal("peer metadata prevented login")
			}
			if mode == "pending" {
				a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7, peer: peer})
				assertPeerAudit(t, logs, "vpn.disconnected", 7, "", 0)
				return
			}
			// Authorization is tested independently with signed SAML fixtures.
			c.active, c.username, c.groupName = true, "verified-user", coreGroup
			c.address, c.expires = netip.MustParseAddr("10.203.0.2"), time.Now().Add(time.Hour)
			established := clientEvent{kind: "ESTABLISHED", cid: 7}
			updated := netip.MustParseAddrPort("198.51.100.25:54322")
			if mode == "established-update" {
				established.peer = updated
				peer = updated
			}
			a.handleEvent(established)
			if peer.IsValid() {
				assertPeerAudit(t, logs, "vpn.tunnel_established", 7, peer.Addr().String(), peer.Port())
			} else {
				assertPeerAudit(t, logs, "vpn.tunnel_established", 7, "", 0)
			}
			if mode == "reauth-update" {
				a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3, peer: updated})
				peer = updated
			}
			disconnect := clientEvent{kind: "DISCONNECT", cid: 7}
			if mode == "disconnect-update" {
				disconnect.peer = updated
				peer = updated
			}
			if mode == "reconciled" {
				disconnect = clientEvent{kind: "STATUS", clients: map[uint64]struct{}{}}
			}
			a.handleEvent(disconnect)
			if peer.IsValid() {
				assertPeerAudit(t, logs, "vpn.disconnected", 7, peer.Addr().String(), peer.Port())
			} else {
				assertPeerAudit(t, logs, "vpn.disconnected", 7, "", 0)
			}
			if a.connections[7] != nil {
				t.Fatal("peer metadata retained a disconnected client")
			}
			logs.mu.Lock()
			logs.buf.Reset()
			logs.mu.Unlock()
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 7, kid: 4, sso: "webauth"})
			c = a.connections[7]
			c.active, c.username = true, "another-verified-user"
			a.handleEvent(clientEvent{kind: "ESTABLISHED", cid: 7})
			assertPeerAudit(t, logs, "vpn.tunnel_established", 7, "", 0)
		})
	}
}
