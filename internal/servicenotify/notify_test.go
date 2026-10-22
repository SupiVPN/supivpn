// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package servicenotify

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessNotification(t *testing.T) {
	dir, err := os.MkdirTemp("", "supi-notify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if sent, err := Ready(); err != nil || !sent {
		t.Fatal("notification not delivered", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatal("invalid readiness message", err)
	}
}

func TestOptionalAndUnavailableManager(t *testing.T) {
	if sent, err := ready(""); err != nil || sent {
		t.Fatal("standalone launch requires a manager")
	}
	for _, path := range []string{"relative", "/nonexistent-supivpn-notify/socket"} {
		if sent, err := ready(path); err == nil || sent {
			t.Fatal("unavailable manager reported ready")
		}
	}
}
