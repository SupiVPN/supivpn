// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
	"supivpn/internal/profile"
)

// Real Community clients, two upstream daemons and one agent. The controller is
// a synthetic mailbox: PostgreSQL/SAML owner enforcement has separate tests.
func TestOpenVPNTransportFallback(t *testing.T) {
	binary, hook := os.Getenv("SUPIVPN_TEST_OPENVPN"), os.Getenv("SUPIVPN_TEST_AGENT")
	linuxClient := os.Getenv("SUPIVPN_TEST_OPENVPN3")
	if binary == "" {
		t.Skip("requires isolated OpenVPN container")
	}
	if hook == "" {
		t.Fatal("missing hook binary")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ca := testVPNCertificate(t, dir)
	key := filepath.Join(dir, "wrapping.key")
	if err := (profile.Issuer{OpenVPN: binary}).EnsureServerKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	wrapping, err := os.ReadFile(key)
	if err != nil {
		t.Fatal("synthetic key unavailable")
	}
	defer clear(wrapping)
	var managers []*management
	for i := range 2 {
		dev := fmt.Sprintf("supiTransport%d", i)
		socket := filepath.Join(dir, fmt.Sprintf("m%d.sock", i))
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		cfg := strings.NewReplacer(
			"port 1194", "port 12194", "dev supivpn0", "dev "+dev,
			"/etc/supivpn/tls/crt.pem", filepath.Join(dir, "crt.pem"),
			"extra-certs /etc/supivpn/tls/chain.pem", "# ephemeral test CA",
			"/etc/supivpn/tls/key.pem", filepath.Join(dir, "key.pem"),
			"/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.pem"),
			"/var/lib/supivpn/tls-crypt-v2-server.key", key,
			"/run/supivpn/management.sock", socket,
			"/opt/supivpn/supivpn", hook,
			"-learn-address\"", "-learn-address -route-device "+dev+" -route-network 10.203.0.0/24\"",
		).Replace(openVPNServerTemplate)
		if i == 1 {
			cfg = strings.ReplaceAll(cfg, "proto udp4", "proto tcp4-server")
			cfg = strings.ReplaceAll(cfg, "port 12194", "port 12443")
		}
		cfg += "\ntls-crypt-v2-verify \"" + hook + " -verify-profile-metadata required\"\nclient-disconnect \"" + hook + " -route-disconnect -route-device " + dev + " -route-network 10.203.0.0/24\"\n"
		path := filepath.Join(dir, fmt.Sprintf("server%d.conf", i))
		writeTestFile(t, path, []byte(cfg))
		startProtocolProcess(t, binary, "--config", path)
		listener.SetDeadline(time.Now().Add(8 * time.Second))
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal("transport management unavailable")
		}
		managers = append(managers, newManagement(conn))
	}
	m := newTransportManagement(managers[0], managers[1])
	t.Cleanup(m.close)
	if err := m.negotiate(); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"state on", "hold release"} {
		if err := m.command(cmd); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for !m.tunnelsInitialized() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !m.tunnelsInitialized() {
		t.Fatal("two daemons did not initialize")
	}
	// A bound but silent UDP endpoint forces a real client transport timeout.
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:12196")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	proofs := map[string]profile.Credential{}
	registered := map[int64]bool{}
	authorized := map[int64]bool{}
	retrying := map[int64]bool{}
	api := remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
		switch op {
		case "register":
			p, ok := proofs[q.ProfileID]
			if !ok || p.Secret != q.ProfileSecret {
				return nil, &agentclient.Error{Status: 403}
			}
			registered[*q.CID] = true
		case "fetch":
			if !registered[*q.CID] || !authorized[*q.CID] {
				return nil, &agentclient.Error{Status: 204}
			}
			d := allowedRemoteDecision(coreGroup)
			d.CID, d.KID = *q.CID, *q.KID
			d.ID = fmt.Sprintf("decision-%d", *q.CID)
			if retrying[*q.CID] {
				d.GroupName, d.DenialReason = "", controller.ConnectionRetryReason
				d.SubjectHash = strings.Repeat("a", 64)
			}
			return d, nil
		}
		return nil, nil
	})
	a, _ := remoteFixture(t, api)
	a.management.close()
	a.attach(m)
	a.config.ProfileBinding = "required"
	a.config.TCPManagementSocket = "/run/supivpn/management-tcp.sock"
	a.pools = newPoolAllocator(a.config)
	template := openVPNClientTemplate
	start, end := strings.Index(template, "<ca>"), strings.Index(template, "</ca>")
	template = template[:start] + "<ca>\n" + string(ca) + "</ca>" + template[end+len("</ca>"):]
	nodeTest := t
	for i, tc := range []struct {
		name      string
		udp, tcp  uint16
		transport int
		retry     bool
	}{{"TCP temporary refusal", 12196, 12443, 1, true}, {"UDP preferred", 12194, 12443, 0, false}, {"UDP unavailable", 12196, 12443, 1, false}, {"existing UDP-only bound", 12194, 0, 0, false}} {
		if !t.Run(tc.name, func(t *testing.T) {
			issue, err := profile.BoundTransportIssuer([]byte(template), "localhost", tc.udp, tc.tcp,
				func(context.Context) ([]byte, error) { return bytes.Clone(wrapping), nil },
				func(_ context.Context, p profile.Credential, _ profile.Owner) error { proofs[p.ID] = p; return nil })
			if err != nil {
				t.Fatal(err)
			}
			data, err := issue(context.Background(), profile.Owner{SubjectHash: sha256.Sum256([]byte("synthetic owner"))})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fmt.Sprintf("client%d.ovpn", i))
			// Avoid platform-specific duplicate localhost resolver entries while
			// preserving the exact localhost certificate-name check.
			data = bytes.ReplaceAll(data, []byte("remote localhost "), []byte("remote 127.0.0.1 "))
			writeTestFile(t, path, data)
			clientBinary := binary
			clientArgs := []string{"--config", path, "--dev", fmt.Sprintf("supiClient%d", i), "--dev-type", "tun", "--disable-dco", "--ifconfig-noexec", "--route-noexec", "--setenv", "IV_SSO", "webauth", "--verb", "3"}
			if linuxClient != "" {
				clientBinary = linuxClient
				// Keep the foreground CLI timeout longer than the deliberate
				// server wait, independently of protocol handshake deadlines.
				clientArgs = []string{"session-start", "--config", path, "--timeout", "120", "--dco", "false"}
				nodeTest.Cleanup(func() {
					cmd := exec.Command(linuxClient, "session-manage", "--config", path, "--disconnect")
					cmd.Stdout, cmd.Stderr = &protocolLog{}, &protocolLog{}
					_ = cmd.Run()
				})
			}
			started := time.Now()
			log := startProtocolProcess(nodeTest, clientBinary, clientArgs...)
			var e clientEvent
			deadline := time.After(30 * time.Second)
			for {
				select {
				case e = <-m.events:
					// OpenVPN 3 can close the old TEMP-refused TCP handshake
					// after its replacement tunnel is already established.
					// Process that real disconnect without mistaking it for
					// the next client's CONNECT or releasing any live tunnel.
					if e.kind == "DISCONNECT" && retrying[int64(e.cid)] {
						a.handleEvent(e)
						remoteStepNow(a)
						continue
					}
				case <-deadline:
					t.Logf("client protocol categories: %v", log.categories())
					for _, marker := range []string{"New tunnel did not respond", "Configuration file import failed", "Could not connect to the session"} {
						if log.contains(marker) {
							t.Log("Linux client diagnostic:", marker)
						}
					}
					t.Fatal("transport did not request authentication")
				}
				break
			}
			if e.kind != "CONNECT" || e.transport != tc.transport || !e.proof.Valid() {
				t.Logf("unexpected event: kind=%s cid=%d transport=%d bound=%t", e.kind, e.cid, e.transport, e.proof.Valid())
				t.Fatal("wrong transport or missing bound proof")
			}
			if tc.transport == 1 {
				elapsed := time.Since(started)
				t.Logf("unresponsive UDP to TCP authentication request: %s", elapsed.Round(time.Millisecond))
				// Include process startup and TLS; detect a silently ignored poll
				// option falling back to the OpenVPN 3 ten-second default.
				if elapsed >= 9*time.Second {
					t.Fatal("client did not apply the short endpoint timeout")
				}
			}
			a.handleEvent(e)
			remoteStepNow(a)
			marker := "WEB_AUTH:external:"
			if linuxClient != "" {
				marker = a.remote.publicURL + "/login/"
			}
			waitProtocol(t, log, marker)
			if tc.name == "UDP preferred" {
				// A responsive endpoint must retain the browser login even after
				// the three-second unreachable-endpoint timeout has passed.
				time.Sleep(4 * time.Second)
				select {
				case <-m.events:
					t.Fatal("endpoint polling interrupted pending browser authorization")
				default:
				}
			}
			if log.contains("Initialization Sequence Completed") {
				t.Fatal("tunnel preceded controller authorization")
			}
			authorized[int64(e.cid)] = true
			if tc.retry {
				retrying[int64(e.cid)] = true
				old := e
				oldTicket := a.connections[e.cid].ticket
				remoteStepNow(a)
				live := i
				if linuxClient != "" {
					live = 0
				}
				if a.connections[e.cid].active || len(a.pools.leases) != live {
					t.Fatal("temporary refusal granted an address")
				}
				retryStart := time.Now()
				remoteStepNow(a) // ACK refusal, retain pending handshake.
				tick := time.NewTicker(50 * time.Millisecond)
				defer tick.Stop()
				deadline := time.After(85 * time.Second)
				for {
					select {
					case event := <-m.events:
						if event.kind == "DISCONNECT" {
							a.handleEvent(event)
							remoteStepNow(a)
							continue
						}
						if event.kind != "CONNECT" || event.cid == old.cid || event.transport != 1 || !event.proof.Valid() {
							t.Fatal("temporary refusal did not preserve TCP and bound proof")
						}
						e = event
					case <-tick.C:
						remoteStepNow(a)
						continue
					case <-deadline:
						t.Fatal("native client did not retry temporary refusal")
					}
					break
				}
				if time.Since(retryStart) < 59*time.Second {
					t.Log("exact temporary failure received:", log.contains("AUTH_FAILED,TEMP[backoff 1,advance no]"))
					t.Log("server temporary reject:", log.contains("auth-temp-failure"))
					t.Fatal("native client ignored retry backoff")
				}
				a.handleEvent(e)
				remoteStepNow(a)
				if a.connections[e.cid].ticket == oldTicket || a.connections[e.cid].active {
					t.Fatal("retry reused authorization")
				}
				// The synthetic controller models a second, fresh SAML decision.
				authorized[int64(e.cid)] = true
				t.Logf("native client retried on TCP after %s with a fresh browser ticket", time.Since(retryStart).Round(time.Second))
			}
			remoteStepNow(a)
			if linuxClient == "" {
				waitProtocol(t, log, "Initialization Sequence Completed")
			}
			select {
			case established := <-m.events:
				if established.kind != "ESTABLISHED" || established.cid != e.cid {
					t.Fatal("wrong established session")
				}
				a.handleEvent(established)
				remoteStepNow(a) // Complete this admission before starting another.
			case <-time.After(15 * time.Second):
				// OpenVPN 3 configures a real interface through D-Bus here. This
				// deadline is independent of the endpoint fallback timing above.
				for _, marker := range []string{"AUTH_FAILED", "TLS_ERROR", "CONNECTION_TIMEOUT", "NETWORK_UNREACHABLE", "TUN_SETUP_FAILED", "Options error", "Initialization Sequence Completed"} {
					if log.contains(marker) {
						t.Log("client diagnostic:", marker)
					}
				}
				t.Fatal("missing tunnel confirmation")
			}
			address := a.connections[e.cid].address.String()
			// OpenVPN 3 configures its real TUN in this same isolated namespace;
			// Linux therefore owns the client address locally. Route selection is
			// checked with Community clients here and separate namespaces in VM.
			if linuxClient != "" {
				// ESTABLISHED comes from the server before the Linux client
				// finishes its D-Bus interface setup. Require client readiness
				// before disconnecting or starting another session.
				untilReady := time.Now().Add(12 * time.Second)
				ready := false
				for time.Now().Before(untilReady) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					out, err := exec.CommandContext(ctx, linuxClient, "sessions-list").Output()
					cancel()
					if err == nil {
						for _, record := range strings.Split(string(out), "Path:") {
							if strings.Contains(record, path) && strings.Contains(record, "Client connected") {
								ready = true
							}
						}
					}
					if ready {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if !ready {
					t.Fatal("Linux client did not report a connected tunnel")
				}
				// D-Bus clients configure real interfaces/routes in the same
				// namespace as these loopback servers. Retire each Linux client
				// before the next one; simultaneous real payload is tested in
				// separate VM namespaces and concurrent allocation below with
				// Community clients that use --ifconfig-noexec/--route-noexec.
				cmd := exec.Command(linuxClient, "session-manage", "--config", path, "--disconnect")
				cmd.Stdout, cmd.Stderr = &protocolLog{}, &protocolLog{}
				if cmd.Run() != nil {
					t.Fatal("cannot disconnect completed Linux test session")
				}
				until := time.After(15 * time.Second)
				for a.connections[e.cid] != nil {
					select {
					case gone := <-m.events:
						if gone.kind != "DISCONNECT" || gone.cid != e.cid && !retrying[int64(gone.cid)] {
							t.Fatal("unexpected event while draining Linux test client")
						}
						a.handleEvent(gone)
						remoteStepNow(a)
					case <-until:
						t.Fatal("Linux test client did not release its slot")
					}
				}
				if len(a.pools.leases) != 0 || len(a.pools.owners) != 0 {
					t.Fatal("Linux test client retained a shared-pool address")
				}
				return
			}
			var routes []hostRoute
			out, err := exec.Command("/usr/sbin/ip", "-j", "-4", "route", "get", address).Output()
			if err != nil || json.Unmarshal(out, &routes) != nil || len(routes) != 1 || routes[0].Device != fmt.Sprintf("supiTransport%d", tc.transport) {
				t.Fatal("authenticated client route selected wrong daemon")
			}
		}) {
			t.FailNow()
		}
	}
	if linuxClient == "" && (len(a.pools.leases) != 4 || len(a.pools.owners) != 4) {
		t.Fatal("transports reused a live address")
	}
}
