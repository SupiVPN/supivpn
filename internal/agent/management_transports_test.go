// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func transportEvent(t *testing.T, m *management) clientEvent {
	t.Helper()
	select {
	case e, ok := <-m.events:
		if !ok {
			t.Fatal("management closed before event")
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("missing transport event")
	}
	return clientEvent{}
}

func TestTransportManagementIsolatesDuplicateClientIDs(t *testing.T) {
	udp, udpCommands := fakeManagement(t)
	tcp, tcpCommands := fakeManagement(t)
	m := newTransportManagement(udp, tcp)
	t.Cleanup(m.close)
	for index, child := range []*management{udp, tcp} {
		child.events <- clientEvent{kind: "CONNECT", cid: 7, kid: 2}
		e := transportEvent(t, m)
		want := uint64(index)*transportCIDBit + 7
		if e.cid != want || !e.scoped || e.transport != index {
			t.Fatal("transport identity collision")
		}
		if err := m.command(fmt.Sprintf("client-auth-nt %d 2", want)); err != nil {
			t.Fatal(err)
		}
		commands, other := udpCommands, tcpCommands
		if index == 1 {
			commands, other = tcpCommands, udpCommands
		}
		if command := <-commands; command != "client-auth-nt 7 2" || len(other) != 0 {
			t.Fatal("authorization reached another daemon")
		}
		if err := m.authorizeIPv4(want, 2, netip.MustParseAddr("10.203.0.2"), "255.255.255.128"); err != nil {
			t.Fatal(err)
		}
		if command := <-commands; command != "client-auth 7 2\nifconfig-push 10.203.0.2 255.255.255.128\nEND" || len(other) != 0 {
			t.Fatal("address reached another daemon")
		}
		if err := m.command(fmt.Sprintf("client-kill %d", want)); err != nil {
			t.Fatal(err)
		}
		if command := <-commands; command != "client-kill 7" || len(other) != 0 {
			t.Fatal("kill reached another daemon")
		}
	}
	if m.tunnelsInitialized() {
		t.Fatal("uninitialized transports became ready")
	}
	udp.initialized.Store(true)
	if m.tunnelsInitialized() {
		t.Fatal("one daemon made both ready")
	}
	tcp.initialized.Store(true)
	if !m.tunnelsInitialized() {
		t.Fatal("initialized transports not ready")
	}
	udp.close()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("failed daemon did not close node")
	}
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("sibling daemon retained management after node failure")
	}
}

func TestTransportStatusCannotCancelSibling(t *testing.T) {
	udp := statusManagement(t, func(string) string { return statusFixture() })
	tcp := statusManagement(t, func(string) string { return statusFixture(7) })
	m := newTransportManagement(udp, tcp)
	t.Cleanup(m.close)
	a := newAgent(config{}, nil)
	a.attach(m)
	for _, cid := range []uint64{7, transportCIDBit + 7} {
		a.connections[cid] = &connection{cid: cid}
	}
	if err := m.requestStatus(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		a.handleEvent(transportEvent(t, m))
	}
	if a.connections[7] != nil || a.connections[transportCIDBit+7] == nil {
		t.Fatal("snapshot discarded another transport's client")
	}
	// Wire order within a daemon is retained across the shared event queue.
	tcp.events <- clientEvent{kind: "DISCONNECT", cid: 7}
	tcp.events <- clientEvent{kind: "CONNECT", cid: 8, kid: 1}
	if e := transportEvent(t, m); e.kind != "DISCONNECT" || e.cid != transportCIDBit+7 {
		t.Fatal("disconnect reordered")
	}
	if e := transportEvent(t, m); e.kind != "CONNECT" || e.cid != transportCIDBit+8 {
		t.Fatal("connect reordered")
	}
}

func TestTransportRejectsClientIDOverflow(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		udp, _ := fakeManagement(t)
		tcp, _ := fakeManagement(t)
		m := newTransportManagement(udp, tcp)
		t.Cleanup(m.close)
		e := clientEvent{kind: "CONNECT", cid: transportCIDBit, kid: 1}
		if snapshot {
			e = clientEvent{kind: "STATUS", clients: map[uint64]struct{}{transportCIDBit: {}}}
		}
		tcp.events <- e
		select {
		case <-m.done:
		case <-time.After(time.Second):
			t.Fatal("out-of-range daemon ID accepted")
		}
		if m.command("client-kill 18446744073709551615") == nil {
			t.Fatal("out-of-range command accepted")
		}
	}
}

func TestTransportAddressAllocationUsesOneAggregate(t *testing.T) {
	c := config{VPNNetwork: "10.203.0.0/24", TCPManagementSocket: "/run/supivpn/management-tcp.sock", SAMLGroupsAttribute: "groups",
		GroupPools: []groupPool{{GroupName: "admins-vpn", Priority: 10, CIDR: "10.203.0.0/25"},
			{GroupName: "engineers-production-vpn", Priority: 20, CIDR: "10.203.0.128/25"}}}
	if err := validateAuthorization(c); err != nil {
		t.Fatal(err)
	}
	p := newPoolAllocator(c)
	for _, tc := range []struct {
		cid       uint64
		group, ip string
	}{{7, "admins-vpn", "10.203.0.2"}, {transportCIDBit + 7, "admins-vpn", "10.203.0.3"}, {8, "engineers-production-vpn", "10.203.0.129"}, {transportCIDBit + 8, "engineers-production-vpn", "10.203.0.130"}} {
		ip, err := p.acquire(tc.cid, tc.group)
		if err != nil || ip.String() != tc.ip || p.netmask() != "255.255.255.0" {
			t.Fatal("incorrect shared address or route mask", err)
		}
	}
	p.release(7)
	if _, ok := p.leases[transportCIDBit+7]; !ok {
		t.Fatal("UDP disconnect released TCP address")
	}
	if _, err := p.acquire(2*transportCIDBit, "admins-vpn"); err == nil {
		t.Fatal("invalid CID allocated address")
	}
	// Every address remains available to either protocol, even if the other
	// transport has no clients at all. TCP enablement must not halve capacity.
	for _, offset := range []uint64{0, transportCIDBit} {
		p = newPoolAllocator(c)
		for cid := uint64(0); cid < 125; cid++ {
			if _, err := p.acquire(offset+cid, "admins-vpn"); err != nil {
				t.Fatal("transport lost pool capacity", err)
			}
		}
		if _, err := p.acquire(offset+125, "admins-vpn"); err != errPoolFull {
			t.Fatal("pool exceeded capacity", err)
		}
	}
}
