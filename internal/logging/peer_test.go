// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestPeerAuditFields(t *testing.T) {
	for _, event := range []string{"vpn.tunnel_established", "vpn.disconnected", "vpn.connection_requested", "saml.response_refused"} {
		var out bytes.Buffer
		New(&out, "agent").Emit(context.Background(), event,
			slog.String("peer_ip", "2001:db8::24"), slog.Uint64("peer_port", 54321))
		row := decode(t, out.String())
		allowed := event == "vpn.tunnel_established" || event == "vpn.disconnected"
		if _, ok := row["peer_ip"]; ok != allowed {
			t.Fatal("peer IP event allowlist mismatch")
		}
		if _, ok := row["peer_port"]; ok != allowed {
			t.Fatal("peer port event allowlist mismatch")
		}
		if allowed && (row["peer_ip"] != "2001:db8::24" || row["peer_port"] != float64(54321)) {
			t.Fatal("peer values changed")
		}
	}
	for _, attrs := range [][]slog.Attr{
		{slog.String("peer_ip", "198.51.100.24\nforged"), slog.String("peer_port", "54321")},
		{slog.String("peer_ip", "example.test"), slog.Int("peer_port", -1)},
		{slog.String("peer_ip", "fe80::1%eth0"), slog.Uint64("peer_port", 65536)},
		{slog.Any("peer_ip", explosiveValue{}), slog.Any("peer_port", explosiveValue{})},
		{slog.String("peer_ip", "198.51.100.24:443"), slog.Int("peer_port", 0)},
	} {
		var out bytes.Buffer
		New(&out, "agent").Emit(context.Background(), "vpn.tunnel_established", attrs...)
		row := decode(t, out.String())
		if _, ok := row["peer_ip"]; ok {
			t.Fatal("invalid peer IP logged")
		}
		if _, ok := row["peer_port"]; ok {
			t.Fatal("invalid peer port logged")
		}
	}
}
