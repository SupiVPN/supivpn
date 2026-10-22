// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"supivpn/internal/logging"
)

func TestServiceReadinessWaitsForListeners(t *testing.T) {
	for _, validTLS := range []bool{true, false} {
		t.Run(map[bool]string{true: "listeners-ready", false: "invalid-tls"}[validTLS], func(t *testing.T) {
			dir, err := os.MkdirTemp("", "supi-ready-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			testVPNCertificate(t, dir)
			_, md := testIdP(t)
			metadata, err := xml.Marshal(md)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(dir, "idp.xml"), metadata)
			writeTestFile(t, filepath.Join(dir, "chain.pem"), nil)
			c := config{PublicURL: "https://localhost", Listen: "127.0.0.1:0",
				Logging:        &logging.Config{Output: "stderr"},
				TLSCertificate: filepath.Join(dir, "crt.pem"), TLSPrivateKey: filepath.Join(dir, "key.pem"),
				TLSChain: filepath.Join(dir, "chain.pem"), IDPMetadata: filepath.Join(dir, "idp.xml"),
				ManagementSocket: filepath.Join(dir, "management.sock"), PendingSeconds: 180,
				SessionSeconds: 3600, AllowedSubjects: []string{"test-user"}}
			if !validTLS {
				c.TLSPrivateKey = filepath.Join(dir, "absent.pem")
			}
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "agent.json")
			writeTestFile(t, path, raw)
			notifyPath := filepath.Join(dir, "notify.sock")
			notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer notify.Close()
			t.Setenv("NOTIFY_SOCKET", notifyPath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- run(ctx, path) }()
			if !validTLS {
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("invalid TLS accepted")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("invalid startup did not stop")
				}
				_ = notify.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if _, _, err := notify.ReadFromUnix(make([]byte, 64)); err == nil {
					t.Fatal("failed service reported ready")
				}
				return
			}
			_ = notify.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 64)
			n, _, err := notify.ReadFromUnix(buf)
			if err != nil || string(buf[:n]) != "READY=1" {
				select {
				case startupErr := <-done:
					t.Fatal("startup failed", startupErr)
				default:
					t.Fatal("service did not report listener readiness", err)
				}
			}
			for _, socket := range []string{c.ManagementSocket, operatorSocket(c.ManagementSocket)} {
				info, err := os.Lstat(socket)
				if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
					t.Fatal("readiness preceded private listener", err)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("managed startup ignored cancellation")
			}
		})
	}
}
