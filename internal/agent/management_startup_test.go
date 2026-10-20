// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"supivpn/internal/profile"
)

type startupRecordingConn struct {
	net.Conn
	log *protocolLog
}

func (c startupRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.log.Write(p[:n])
	return n, err
}

// Match the deployed daemon startup, including time spent registering with the
// controller while OpenVPN waits on its management hold. No AWS calls are made.
func TestOpenVPNManagementStartup(t *testing.T) {
	binary := os.Getenv("SUPIVPN_TEST_OPENVPN")
	if binary == "" {
		t.Skip("requires isolated OpenVPN test container")
	}
	for _, daemon := range []bool{false, true} {
		name := "foreground"
		if daemon { name = "daemon" }
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
			testVPNCertificate(t, dir)
			key := filepath.Join(dir, "wrapping.key")
			if err := (profile.Issuer{OpenVPN: binary}).EnsureServerKey(context.Background(), key); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(dir, "management.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil { t.Fatal(err) }
			defer listener.Close()
			config := strings.NewReplacer(
				"/etc/supivpn/tls/crt.pem", filepath.Join(dir, "crt.pem"),
				"extra-certs /etc/supivpn/tls/chain.pem", "# no intermediate for test CA",
				"/etc/supivpn/tls/key.pem", filepath.Join(dir, "key.pem"),
				"/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.pem"),
				"/var/lib/supivpn/tls-crypt-v2-server.key", key,
				"/run/supivpn/management.sock", socket,
				"learn-address \"/opt/supivpn/supivpn -learn-address\"", "# no clients in startup test",
			).Replace(openVPNServerTemplate)
			path := filepath.Join(dir, "server.conf")
			writeTestFile(t, path, []byte(config))
			args := []string{"--config", path}
			if daemon { args = append(args, "--daemon", "supivpn-test") }
			startProtocolProcess(t, binary, args...)
			listener.SetDeadline(time.Now().Add(8*time.Second))
			conn, err := listener.AcceptUnix()
			if err != nil { t.Fatal("management did not connect") }
			wire := &protocolLog{}
			m := newManagement(startupRecordingConn{Conn: conn, log: wire})
			defer m.close()
			if err := m.negotiate(); err != nil { t.Fatal(err) }
			// Exercise immediate release as well as a controller registration delay.
			if daemon { time.Sleep(300*time.Millisecond) }
			for _, command := range []string{"state on", "hold release"} {
				if err := m.command(command); err != nil {
					wire.mu.Lock()
					holds := strings.Count(wire.b.String(), ">HOLD:")
					errors := strings.Count(wire.b.String(), "ERROR:")
					successes := strings.Count(wire.b.String(), "SUCCESS:")
					wire.mu.Unlock()
					t.Fatalf("%s: %v (HOLD=%d ERROR=%d SUCCESS=%d; raw output withheld)", command, err, holds, errors, successes)
				}
			}
			deadline := time.Now().Add(5*time.Second)
			for !m.initialized.Load() && time.Now().Before(deadline) { time.Sleep(10*time.Millisecond) }
			if !m.initialized.Load() { t.Fatal("OpenVPN did not initialize") }
			if err := m.command("pid"); err != nil { t.Fatal(err) }
			// Wait for the owned daemon to close management after TUN shutdown,
			// so subsequent cases cannot race with its UDP port cleanup.
			_ = m.command("signal SIGTERM")
			select {
			case <-m.done:
			case <-time.After(5*time.Second): t.Fatal("test daemon did not stop")
			}
		})
	}
}
