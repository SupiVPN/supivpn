// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux || darwin

package unixpeer

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelPeerUIDBothDirections(t *testing.T) {
	dir, err := os.MkdirTemp("", "supi-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := &net.UnixAddr{Name: filepath.Join(dir, "peer.sock"), Net: "unix"}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []*net.UnixConn{client, server} {
		if uid, err := UID(conn); err != nil || uid != uint32(os.Geteuid()) {
			t.Fatal("kernel peer UID mismatch")
		}
		conn.Close()
		if _, err := UID(conn); err == nil {
			t.Fatal("closed socket supplied credentials")
		}
	}
}
