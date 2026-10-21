// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
)

func statusFixture(cids ...uint64) string {
	lines := []string{"TITLE\tOpenVPN 2.7.8 test", "TIME\tfixture time\t100", clientStatusHeader}
	for _, cid := range cids {
		lines = append(lines, fmt.Sprintf("CLIENT_LIST\tUNDEF\t127.0.0.1:1\t\t\t0\t0\tfixture time\t100\tUNDEF\t%d\t0\tAES-256-GCM", cid))
	}
	return strings.Join(append(lines, routeStatusHeader, "GLOBAL_STATS\tMax bcast/mcast queue length\t0", "GLOBAL_STATS\tdco_enabled\t0", "END", ""), "\n")
}

func statusManagement(t *testing.T, response func(string) string) *management {
	t.Helper()
	client, server := net.Pipe()
	m := newManagement(client)
	t.Cleanup(func() { m.close(); server.Close() })
	go func() {
		scanner := bufio.NewScanner(server)
		var transaction []string
		for scanner.Scan() {
			command := scanner.Text()
			if transaction != nil || strings.HasPrefix(command, "client-auth ") {
				transaction = append(transaction, command)
				if command != "END" {
					continue
				}
				command = strings.Join(transaction, "\n")
				transaction = nil
			}
			if _, err := fmt.Fprint(server, response(command)); err != nil {
				return
			}
		}
	}()
	return m
}

func consumeStatus(t *testing.T, a *agent) {
	t.Helper()
	if err := a.management.requestStatus(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-a.management.events:
		if e.kind != "STATUS" {
			t.Fatalf("expected status, got %s", e.kind)
		}
		a.handleEvent(e)
	case <-time.After(time.Second):
		t.Fatal("status event missing")
	}
}

func TestManagementStatusParser(t *testing.T) {
	valid := statusFixture(0, 42)
	cases := map[string]string{
		"missing-title":   strings.TrimPrefix(valid, "TITLE\tOpenVPN 2.7.8 test\n"),
		"missing-time":    strings.Replace(valid, "TIME\tfixture time\t100\n", "", 1),
		"early-end":       "END\n",
		"incomplete":      strings.TrimSuffix(valid, "END\n"),
		"bad-header":      strings.Replace(valid, "Client ID", "Unknown ID", 1),
		"duplicate-cid":   statusFixture(42, 42),
		"negative-cid":    strings.Replace(valid, "\t42\t0\tAES", "\t-1\t0\tAES", 1),
		"overflow-cid":    strings.Replace(valid, "\t42\t0\tAES", "\t18446744073709551616\t0\tAES", 1),
		"injected-column": strings.Replace(valid, "\tUNDEF\t0\t", "\tUNDEF\tforged\t0\t", 1),
		"injected-row":    strings.Replace(valid, "\tUNDEF\t0\t", "\tUNDEF\nEND\n\t0\t", 1),
		"command-error":   "ERROR: status failed\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var parser managementStatus
			for _, line := range strings.Split(strings.TrimSuffix(input, "\n"), "\n") {
				done, err := parser.line(line)
				if done {
					t.Fatal("invalid snapshot accepted")
				}
				if err != nil {
					return
				}
			}
		})
	}
	for _, input := range []string{statusFixture(), valid} {
		var parser managementStatus
		lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")
		for i, line := range lines {
			done, err := parser.line(line)
			if err != nil || done != (i == len(lines)-1) {
				t.Fatal("valid snapshot rejected or completed early")
			}
		}
	}
	var parser managementStatus
	for i := 0; i < 257; i++ {
		_, _ = parser.line("invalid")
	}
	if done, err := parser.line("END"); done || err == nil {
		t.Fatal("unbounded response accepted")
	}
}

func TestManagementStatusKeepsWireOrder(t *testing.T) {
	m := statusManagement(t, func(command string) string {
		if command != "status 3" {
			return "SUCCESS: acknowledged\n"
		}
		return ">CLIENT:CONNECT,7,1\n>CLIENT:ENV,IV_SSO=webauth\n>CLIENT:ENV,END\n" + statusFixture(7) +
			">CLIENT:CONNECT,8,1\n>CLIENT:ENV,IV_SSO=webauth\n>CLIENT:ENV,END\n"
	})
	if err := m.requestStatus(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"CONNECT", "STATUS", "CONNECT"} {
		select {
		case e := <-m.events:
			if e.kind != kind {
				t.Fatalf("event order: %s, want %s", e.kind, kind)
			}
		case <-time.After(time.Second):
			t.Fatal("missing ordered event")
		}
	}
	if err := m.command("pid"); err != nil {
		t.Fatal("status response corrupted the next exchange", err)
	}
}

func TestCancelledLoginSlotReconciliation(t *testing.T) {
	for _, lateSAML := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-authorization=%t", lateSAML), func(t *testing.T) {
			origin, _ := url.Parse("https://vpn.example.test")
			a := newAgent(groupConfig(), origin)
			a.pools = newPoolAllocator(a.config)
			// The response channel gives the test explicit control over daemon
			// evidence without racing the management reader.
			responses := make(chan string, 4)
			m := statusManagement(t, func(command string) string {
				if command == "status 3" {
					return <-responses
				}
				return "SUCCESS: acknowledged\n"
			})
			a.attach(m)
			now := time.Now()
			decision := controller.Authorization{SubjectHash: sha256.Sum256([]byte("verified-issuer\x00user")),
				MaxConnections: 1, GroupName: coreGroup, NotBefore: now.Add(-time.Minute),
				NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(10 * time.Minute)}
			pending := func(cid uint64) *connection {
				c := &connection{cid: cid, kid: 1, revision: cid, ticket: fmt.Sprint("ticket-", cid),
					requestID: fmt.Sprint("request-", cid), expires: now.Add(time.Minute), browserHash: sha256.Sum256([]byte("synthetic-browser"))}
				a.connections[cid], a.tickets[c.ticket] = c, c
				return c
			}
			old := pending(7)
			if lateSAML {
				if err := a.Complete(context.Background(), pendingSnapshot(old), decision); err != nil {
					t.Fatal(err)
				}
			}
			attempt := pending(8)
			err := a.Complete(context.Background(), pendingSnapshot(attempt), decision)
			if lateSAML && !errors.Is(err, controller.ErrConnectionLimit) {
				t.Fatal("live grant bypassed the user limit")
			}
			if !lateSAML && err != nil {
				t.Fatal("unauthenticated attempt consumed a personal slot", err)
			}
			responses <- statusFixture(7, 8)
			consumeStatus(t, a)
			if a.connections[7] != old {
				t.Fatal("live CID was released")
			}
			responses <- statusFixture(8)
			consumeStatus(t, a)
			if a.connections[7] != nil || a.tickets[old.ticket] != nil {
				t.Fatal("absent CID retained login state")
			}
			if lateSAML {
				fresh := pending(9)
				if err := a.Complete(context.Background(), pendingSnapshot(fresh), decision); err != nil {
					t.Fatal("confirmed absence did not release the user slot", err)
				}
			}
			if len(a.pools.leases) != 1 || !a.readyLocked() {
				t.Fatal("reconciliation disrupted the remaining session or leaked an IP")
			}
		})
	}
}

func TestRejectedKillRequiresConfirmedAbsence(t *testing.T) {
	for _, response := range []string{statusFixture(), statusFixture(7), "ERROR: unavailable\n"} {
		origin, _ := url.Parse("https://vpn.example.test")
		a := newAgent(config{}, origin)
		m := statusManagement(t, func(command string) string {
			if command == "status 3" {
				return response
			}
			return "ERROR: client-kill command failed\n"
		})
		a.attach(m)
		c := &connection{cid: 7, kid: 1, active: true}
		a.connections[7] = c
		a.closeClientLocked(c)
		if a.connections[7] == nil {
			t.Fatal("rejection released the slot without daemon evidence")
		}
		if strings.HasPrefix(response, "ERROR") {
			if a.readyLocked() {
				t.Fatal("uncertain daemon remained available")
			}
			continue
		}
		a.handleEvent(<-m.events)
		wantRemoved := response == statusFixture()
		if (a.connections[7] == nil) != wantRemoved {
			t.Fatal("CID presence was not respected")
		}
	}
}

func TestIncompleteStatusCannotReleaseConnections(t *testing.T) {
	client, server := net.Pipe()
	m := newManagement(client)
	t.Cleanup(m.close)
	go func() {
		defer server.Close()
		_, _ = bufio.NewReader(server).ReadString('\n')
		_, _ = fmt.Fprint(server, strings.TrimSuffix(statusFixture(), "END\n"))
	}()
	if err := m.requestStatus(); err == nil {
		t.Fatal("truncated snapshot accepted")
	}
	select {
	case _, ok := <-m.events:
		if ok {
			t.Fatal("partial snapshot became authoritative")
		}
	default:
	}
	select {
	case <-m.done:
	default:
		t.Fatal("uncertain management connection stayed open")
	}
}

func FuzzManagementStatus(f *testing.F) {
	f.Add(statusFixture())
	f.Add(statusFixture(0, 7))
	f.Add("END\n")
	f.Add("TITLE\tOpenVPN fixture\nTIME\tnow\t0\n" + clientStatusHeader + "\nCLIENT_LIST\tforged\nEND\n")
	f.Fuzz(func(t *testing.T, input string) {
		var parser managementStatus
		for _, line := range strings.Split(input, "\n") {
			done, err := parser.line(line)
			if len(parser.clients) > 64 {
				t.Fatal("unbounded CID set")
			}
			if err != nil {
				if done {
					t.Fatal("failed snapshot completed")
				}
				return
			}
			if done {
				if parser.clients == nil {
					t.Fatal("missing client section")
				}
				return
			}
		}
	})
}
