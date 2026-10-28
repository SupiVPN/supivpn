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
	}{{"UDP preferred", 12194, 12443, 0}, {"UDP unavailable", 12196, 12443, 1}, {"existing UDP-only bound", 12194, 0, 0}} {
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
				clientArgs = []string{"session-start", "--config", path, "--timeout", "45", "--dco", "false"}
				nodeTest.Cleanup(func() {
					cmd := exec.Command(linuxClient, "session-manage", "--config", path, "--disconnect")
					cmd.Stdout, cmd.Stderr = &protocolLog{}, &protocolLog{}
					_ = cmd.Run()
				})
			}
			started := time.Now()
			log := startProtocolProcess(nodeTest, clientBinary, clientArgs...)
			var e clientEvent
			select {
			case e = <-m.events:
			case <-time.After(30 * time.Second):
				t.Fatal("transport did not request authentication")
			}
			if e.kind != "CONNECT" || e.transport != tc.transport || !e.proof.Valid() {
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
			if i == 0 {
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
	if len(a.pools.leases) != 3 || len(a.pools.owners) != 3 {
		t.Fatal("transports reused a live address")
	}
}
