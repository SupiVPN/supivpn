// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/profile"
)

// Abrupt cancellation deliberately sends no exit notification. The daemon can
// discard a handshake without emitting CLIENT:DISCONNECT. A late verified SAML
// decision must not leave a user reservation after that CID is gone.
func TestOpenVPNCancelledLoginReleasesSlot(t *testing.T) {
	binary, hook := os.Getenv("SUPIVPN_TEST_OPENVPN"), os.Getenv("SUPIVPN_TEST_AGENT")
	if binary == "" {
		t.Skip("requires isolated Linux OpenVPN container")
	}
	if hook == "" {
		t.Fatal("SUPIVPN_TEST_AGENT required")
	}
	for _, tc := range []struct {
		name                              string
		tcp, lateDecision, dropDisconnect bool
	}{
		{"udp/cancel-before-saml", false, false, false},
		{"udp/saml-after-cancel", false, true, false},
		{"tcp/cancel-before-saml", true, false, false},
		{"udp/missing-disconnect", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ca := testVPNCertificate(t, dir)
			key := filepath.Join(dir, "wrapping.key")
			issuer := profile.Issuer{OpenVPN: binary}
			if err := issuer.EnsureServerKey(context.Background(), key); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(dir, "management.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			config := strings.NewReplacer(
				"/etc/supivpn/tls/crt.pem", filepath.Join(dir, "crt.pem"),
				"extra-certs /etc/supivpn/tls/chain.pem", "# ephemeral test CA",
				"/etc/supivpn/tls/key.pem", filepath.Join(dir, "key.pem"),
				"/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.pem"),
				"/var/lib/supivpn/tls-crypt-v2-server.key", key,
				"/run/supivpn/management.sock", socket,
				"/opt/supivpn/supivpn", hook,
				"hand-window 180", "hand-window 8",
				"keepalive 10 60", "keepalive 1 3",
				"verb 2", "verb 3",
			).Replace(openVPNServerTemplate)
			if tc.tcp {
				config = strings.Replace(config, "proto udp4", "proto tcp4-server", 1)
			}
			serverConfig := filepath.Join(dir, "server.conf")
			writeTestFile(t, serverConfig, []byte(config))
			serverLog := startProtocolProcess(t, binary, "--config", serverConfig)
			listener.(*net.UnixListener).SetDeadline(time.Now().Add(8 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal("management unavailable")
			}
			m := newManagement(conn)
			t.Cleanup(m.close)
			if err := m.negotiate(); err != nil {
				t.Fatal(err)
			}
			if err := m.command("hold release"); err != nil {
				t.Fatal(err)
			}
			waitProtocol(t, serverLog, "Initialization Sequence Completed")
			template := strings.Replace(openVPNClientTemplate, "remote supivpn.example.test 1194", "remote 127.0.0.1 1194", 1)
			if tc.tcp {
				template = strings.Replace(template, "proto udp4", "proto tcp4-client", 1)
			}
			start, end := strings.Index(template, "<ca>"), strings.Index(template, "</ca>")
			template = template[:start] + "<ca>\n" + string(ca) + "</ca>" + template[end+len("</ca>"):]
			clientConfig := filepath.Join(dir, "client.ovpn")
			if err := issuer.Issue(context.Background(), key, []byte(template), clientConfig); err != nil {
				t.Fatal(err)
			}
			auth := filepath.Join(dir, "test-auth")
			writeTestFile(t, auth, []byte("unused-test\nunused-test\n"))
			startClient := func() (*protocolLog, func()) {
				t.Helper()
				ctx, cancel := context.WithCancel(context.Background())
				cmd := exec.CommandContext(ctx, binary, "--config", clientConfig, "--auth-user-pass", auth,
					"--dev", "supivpnc", "--dev-type", "tun", "--disable-dco", "--ifconfig-noexec", "--route-noexec",
					"--setenv", "IV_SSO", "webauth", "--verb", "3")
				log := &protocolLog{}
				cmd.Stdout, cmd.Stderr = log, log
				if err := cmd.Start(); err != nil {
					cancel()
					t.Fatal("client start failed")
				}
				var once sync.Once
				stop := func() { once.Do(func() { cancel(); _ = cmd.Wait() }) }
				t.Cleanup(stop)
				return log, stop
			}
			origin, _ := url.Parse("https://vpn.example.test")
			a := newAgent(groupConfig(), origin)
			a.config.PendingSeconds = 5 // Shorten only the isolated fixture's handshake deadline.
			a.pools = newPoolAllocator(a.config)
			a.attach(m)
			connect := func() *connection {
				t.Helper()
				deadline := time.After(10 * time.Second)
				for {
					select {
					case event, ok := <-m.events:
						if !ok {
							t.Fatal("management closed before connection")
						}
						a.handleEvent(event)
						if event.kind != "CONNECT" {
							continue
						}
						return a.connections[event.cid]
					case <-deadline:
						t.Fatal("client did not request login")
					}
				}
			}
			complete := func(c *connection) error {
				t.Helper()
				browser := sha256.Sum256([]byte("synthetic-browser"))
				if err := a.Start(context.Background(), c.ticket, "synthetic-request", browser); err != nil {
					return err
				}
				now := time.Now()
				return a.Complete(context.Background(), pendingSnapshot(c), controller.Authorization{
					SubjectHash:    sha256.Sum256([]byte("synthetic-issuer\x00synthetic-user")),
					MaxConnections: 1, GroupName: coreGroup, NotBefore: now.Add(-time.Minute),
					NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(10 * time.Minute),
				})
			}
			log, cancel := startClient()
			old := connect()
			waitProtocol(t, log, "WEB_AUTH:external:")
			cancel()
			if tc.lateDecision {
				if err := complete(old); err != nil {
					t.Fatal("late synthetic authorization failed", err)
				}
				retryLog, stopRetry := startClient()
				retry := connect()
				waitProtocol(t, retryLog, "WEB_AUTH:external:")
				if err := complete(retry); !errors.Is(err, controller.ErrConnectionLimit) {
					t.Fatal("expected the reported temporary limit while the old CID is still live", err)
				}
				stopRetry()
			}
			// The daemon cannot detect a silent UDP cancellation immediately. Once
			// it removes the instance, cleanup must not depend on DISCONNECT.
			ctx, stopEvents := context.WithCancel(context.Background())
			stopped := make(chan struct{})
			eventSource := m
			var forwarded chan struct{}
			if tc.dropDisconnect {
				// Explicit fault injection: retain the real daemon and commands,
				// but omit the cancelled CID's disconnect notification.
				eventSource = &management{events: make(chan clientEvent, 64), done: m.done}
				filtered := eventSource
				forwarded = make(chan struct{})
				go func() {
					defer close(forwarded)
					for {
						select {
						case e, ok := <-m.events:
							if !ok {
								return
							}
							if e.kind == "DISCONNECT" && e.cid == old.cid {
								continue
							}
							select {
							case filtered.events <- e:
							case <-ctx.Done():
								return
							}
						case <-ctx.Done():
							return
						}
					}
				}()
				t.Cleanup(func() { stopEvents(); <-forwarded })
			}
			go func() { defer close(stopped); a.events(ctx, eventSource) }()
			t.Cleanup(func() { stopEvents(); <-stopped })
			deadline := time.Now().Add(20 * time.Second)
			for {
				a.mu.Lock()
				ready, removed := a.readyLocked(), a.connections[old.cid] == nil
				a.mu.Unlock()
				if !ready {
					t.Fatal("abandoned handshake stopped unrelated clients")
				}
				if removed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cancelled handshake retained a stale connection and user slot")
				}
				time.Sleep(20 * time.Millisecond)
			}
			// Return to synchronous event handling for the fresh connection.
			stopEvents()
			<-stopped
			if forwarded != nil {
				<-forwarded
			}
			freshLog, _ := startClient()
			fresh := connect()
			waitProtocol(t, freshLog, "WEB_AUTH:external:")
			if err := complete(fresh); err != nil {
				t.Fatal("retry could not reuse released user slot", err)
			}
			waitProtocol(t, freshLog, "Initialization Sequence Completed")
		})
	}
}
