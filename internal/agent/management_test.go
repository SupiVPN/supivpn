// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestManagementVersionIsAcknowledged(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	defer m.close()
	defer server.Close()
	commands := make(chan string, 2)
	go func() {
		fmt.Fprintln(server, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
		s := bufio.NewScanner(server)
		for s.Scan() {
			command := s.Text()
			commands <- command
			fmt.Fprintln(server, "SUCCESS: acknowledged")
		}
	}()
	if err := m.negotiate(); err != nil {
		t.Fatal(err)
	}
	if err := m.command("hold release"); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"version 5", "hold release"} {
		select {
		case actual := <-commands:
			if actual != expected {
				t.Fatalf("expected command %q", expected)
			}
		case <-time.After(time.Second):
			t.Fatal("command not sent")
		}
	}
}

func TestManagementVersionACKCannotAuthorizeNextCommand(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	defer m.close()
	defer server.Close()
	versionSent := make(chan struct{})
	go func() {
		fmt.Fprintln(server, ">INFO:OpenVPN Management Interface Version 5 -- test")
		s := bufio.NewScanner(server)
		if s.Scan() && s.Text() == "version 5" {
			fmt.Fprintln(server, "SUCCESS: Management client version set to 5")
		}
		close(versionSent)
		if s.Scan() { fmt.Fprintln(server, "ERROR: hold refused") }
	}()
	if err := m.negotiate(); err != nil { t.Fatal(err) }
	select {
	case <-versionSent:
	case <-time.After(time.Second): t.Fatal("version command not received")
	}
	if err := m.command("hold release"); err == nil {
		t.Fatal("version ACK accepted as hold release confirmation")
	}
}

func TestManagementVersionWaitsForACK(t *testing.T) {
	for _, reply := range []string{"SUCCESS: version accepted", "ERROR: version rejected", ""} {
		t.Run(reply, func(t *testing.T) {
			client, peer := net.Pipe()
			m := newManagement(client)
			defer m.close()
			defer peer.Close()
			result := make(chan error, 1)
			go func() { result <- m.negotiate() }()
			fmt.Fprintln(peer, ">INFO:OpenVPN Management Interface Version 5 -- test")
			peer.SetReadDeadline(time.Now().Add(time.Second))
			s := bufio.NewScanner(peer)
			if !s.Scan() || s.Text() != "version 5" { t.Fatal("version not requested") }
			select {
			case <-result: t.Fatal("negotiation completed without an ACK")
			case <-time.After(20*time.Millisecond):
			}
			if reply == "" { peer.Close() } else { fmt.Fprintln(peer, reply) }
			select {
			case err := <-result:
				if (err == nil) != strings.HasPrefix(reply, "SUCCESS:") { t.Fatal("incorrect negotiation result") }
			case <-time.After(time.Second): t.Fatal("negotiation did not finish")
			}
		})
	}
}

func TestManagementEventsAndAcknowledgments(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	defer m.close()
	defer server.Close()
	go func() {
		s := bufio.NewScanner(server)
		if s.Scan() {
			fmt.Fprint(server, ">CLIENT:CONNECT,7,2\n>CLIENT:ENV,IV_SSO=webauth,crtext\n>CLIENT:ENV,password=unused-test-input\n>CLIENT:ENV,END\nSUCCESS: accepted\n")
		}
		if s.Scan() {
			fmt.Fprintln(server, "ERROR: rejected")
		}
	}()
	if err := m.command("hold release"); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-m.events:
		if e.cid != 7 || e.kid != 2 || !supportsWebAuth(e.sso) {
			t.Fatal("incorrect event")
		}
	case <-time.After(time.Second):
		t.Fatal("missing event")
	}
	if err := m.command("client-auth-nt 7 2"); err == nil {
		t.Fatal("rejection treated as success")
	}
}

func TestDisconnectInvalidatesCommands(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	defer m.close()
	server.Close()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("disconnect not detected")
	}
	if m.command("client-auth-nt 1 1") == nil {
		t.Fatal("closed connection authorized")
	}
}

func TestClientIdentifiersAndCapability(t *testing.T) {
	for _, line := range []string{">CLIENT:CONNECT,-1,2", ">CLIENT:CONNECT,1", ">CLIENT:REAUTH,1,2\nclient-auth-nt 3 4"} {
		if _, err := parseClientHeader(line); err == nil {
			t.Fatal("malformed event accepted")
		}
	}
	for _, value := range []string{"", "openurl", "notwebauth", "webauth.invalid"} {
		if supportsWebAuth(value) {
			t.Fatal("unsupported client accepted")
		}
	}
	if !supportsWebAuth(strings.Join([]string{"crtext", "webauth"}, ",")) {
		t.Fatal("webauth missing")
	}
}

func TestClientConfigWaitsForEndAndAck(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	defer m.close()
	defer server.Close()
	if err := m.command("hold release\nclient-auth-nt 1 1"); err == nil {
		t.Fatal("multiline injection accepted")
	}
	if err := m.authorizeIPv4(7, 2, netip.MustParseAddr("10.203.0.2"), "255.255.255.0\nEND"); err == nil {
		t.Fatal("mask injection accepted")
	}
	result := make(chan error, 1)
	go func() { result <- m.authorizeIPv4(7, 2, netip.MustParseAddr("10.203.0.2"), "255.255.255.0") }()
	server.SetReadDeadline(time.Now().Add(time.Second))
	scanner := bufio.NewScanner(server)
	for _, expected := range []string{"client-auth 7 2", "ifconfig-push 10.203.0.2 255.255.255.0", "END"} {
		if !scanner.Scan() || scanner.Text() != expected {
			t.Fatal("incomplete client configuration transaction")
		}
	}
	select {
	case <-result:
		t.Fatal("authorized without ACK")
	default:
	}
	fmt.Fprintln(server, "ERROR: rejected")
	if <-result == nil {
		t.Fatal("client config rejection treated as authorization")
	}
}
