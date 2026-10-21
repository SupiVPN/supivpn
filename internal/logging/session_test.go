// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestSessionAuditFieldValidation(t *testing.T) {
	fields := []slog.Attr{slog.String("client_version", "3.11.0 (release)"), slog.String("client_platform", "android"),
		slog.Int64("establishment_ms", 2345), slog.Uint64("duration_seconds", 0), slog.Uint64("bytes_received", 123),
		slog.Uint64("bytes_sent", 456), slog.String("disconnect_source", "management_event"), slog.String("disconnect_reason", "operator_requested")}
	for _, event := range []string{"vpn.tunnel_established", "vpn.disconnected", "vpn.connection_requested", "saml.login_started"} {
		var out bytes.Buffer
		New(&out, "agent").Emit(context.Background(), event, fields...)
		row := decode(t, out.String())
		for _, field := range fields {
			want := event == "vpn.tunnel_established" && (field.Key == "client_version" || field.Key == "client_platform" || field.Key == "establishment_ms") || event == "vpn.disconnected" && field.Key != "client_version" && field.Key != "client_platform" && field.Key != "establishment_ms"
			if _, ok := row[field.Key]; ok != want {
				t.Fatal("incorrect event field allowlist", event, field.Key)
			}
		}
	}
	for _, field := range []slog.Attr{slog.String("client_version", "v1\nforged"), slog.String("client_platform", "linux\tforged"),
		slog.String("client_version", strings.Repeat("a", 129)), slog.String("client_platform", strings.Repeat("a", 33)),
		slog.String("client_version", "v1\u202eforged"), slog.Int("duration_seconds", -1), slog.String("bytes_received", "12"),
		slog.Any("bytes_sent", explosiveValue{}), slog.Float64("establishment_ms", 1.5), slog.String("disconnect_source", "forged"),
		slog.String("disconnect_reason", "client_clicked_disconnect")} {
		var out bytes.Buffer
		event := "vpn.disconnected"
		if strings.HasPrefix(field.Key, "client_") || field.Key == "establishment_ms" {
			event = "vpn.tunnel_established"
		}
		New(&out, "agent").Emit(context.Background(), event, field)
		if _, ok := decode(t, out.String())[field.Key]; ok {
			t.Fatal("invalid session field logged", field.Key)
		}
	}
}
