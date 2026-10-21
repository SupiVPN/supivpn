// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"strconv"
	"strings"

	"supivpn/internal/logging"
)

type clientInfo struct{ version, platform string }

type auditCounter struct {
	value         uint64
	seen, invalid bool
}

func (c *auditCounter) add(value string) {
	if c.seen || len(value) == 0 || len(value) > 20 {
		c.invalid = true
	}
	c.seen = true
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		c.invalid = true
	}
	c.value = n
}

type disconnectMetrics struct{ duration, received, sent auditCounter }

// Only explicitly selected fields survive each environment block. Client labels
// are self-reported diagnostics; counters are accepted only on DISCONNECT.
type sessionEnvironment struct {
	client                    clientInfo
	seenVersion, seenPlatform bool
	metrics                   disconnectMetrics
}

func (s *sessionEnvironment) add(kind, env string) {
	name, value, ok := strings.Cut(env, "=")
	if !ok {
		return
	}
	if kind == "CONNECT" {
		switch name {
		case "IV_VER":
			if !s.seenVersion && logging.ValidClientVersion(value) {
				s.client.version = value
			} else {
				s.client.version = ""
			}
			s.seenVersion = true
		case "IV_PLAT":
			if !s.seenPlatform && logging.ValidClientPlatform(value) {
				s.client.platform = value
			} else {
				s.client.platform = ""
			}
			s.seenPlatform = true
		}
	} else if kind == "DISCONNECT" {
		switch name {
		case "time_duration":
			s.metrics.duration.add(value)
		case "bytes_received":
			s.metrics.received.add(value)
		case "bytes_sent":
			s.metrics.sent.add(value)
		}
	}
}

func (a *agent) logDisconnect(c *connection, source string, metrics disconnectMetrics) {
	attrs := []slog.Attr{slog.String("disconnect_source", source)}
	if c.disconnectReason != "" {
		attrs = append(attrs, slog.String("disconnect_reason", c.disconnectReason))
	}
	if c.active {
		for _, field := range []struct {
			key     string
			counter auditCounter
		}{
			{"duration_seconds", metrics.duration}, {"bytes_received", metrics.received}, {"bytes_sent", metrics.sent},
		} {
			if field.counter.seen && !field.counter.invalid {
				attrs = append(attrs, slog.Uint64(field.key, field.counter.value))
			}
		}
	}
	a.logTunnelEvent("vpn.disconnected", c, attrs...)
}
