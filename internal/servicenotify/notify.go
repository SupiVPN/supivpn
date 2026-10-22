// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package servicenotify reports listener readiness to a systemd service manager.
package servicenotify

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// Ready is a no-op outside a notifying service. It never reports VPN readiness:
// the agent's /readyz remains the authority for management/lease readiness.
func Ready() (bool, error) {
	return ready(os.Getenv("NOTIFY_SOCKET"))
}

func ready(socket string) (bool, error) {
	if socket == "" {
		return false, nil
	}
	refused := errors.New("service readiness notification failed")
	if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") {
		return false, refused
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return false, refused
	}
	defer conn.Close()
	if err = conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return false, refused
	}
	if _, err = conn.Write([]byte("READY=1")); err != nil {
		return false, refused
	}
	return true, nil
}
