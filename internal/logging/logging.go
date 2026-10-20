// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package logging emits bounded, allowlisted operational events. It never accepts
// arbitrary messages, error objects, HTTP requests, assertions or configuration.
package logging

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"supivpn/internal/tracecontext"
)

type definition struct {
	level   slog.Level
	message string
	fields  string
}

// Event names and schema_version are the machine-readable contract. Messages
// are for humans. Never derive an event name or message from request data.
var events = map[string]definition{
	"vpn.connection_requested":       {slog.LevelInfo, "VPN connection requested", ""},
	"vpn.tls_reauthenticated":        {slog.LevelInfo, "Existing VPN session accepted a TLS rekey", ""},
	"agent.login_registered":         {slog.LevelInfo, "Agent login registration committed", ""},
	"agent.decision_delivered":       {slog.LevelInfo, "Authorization decision returned to the agent", ""},
	"agent.decision_acknowledged":    {slog.LevelInfo, "Agent authorization outcome committed", "outcome"},
	"agent.connection_cancelled":     {slog.LevelInfo, "Agent connection cancellation committed", ""},
	"saml.request_refused":           {slog.LevelWarn, "Browser request refused", "status"},
	"logging.output_failed":           {slog.LevelError, "Log file unavailable; application logging switched to stderr until restart", ""},
	"vpn.authentication_refused":      {slog.LevelWarn, "VPN authentication refused", "reason"},
	"vpn.browser_auth_requested":      {slog.LevelInfo, "VPN browser authentication requested", ""},
	"vpn.tunnel_established":          {slog.LevelInfo, "VPN tunnel established", "username group_name address"},
	"vpn.disconnected":                {slog.LevelInfo, "VPN disconnected", "username group_name address"},
	"vpn.session_expired":             {slog.LevelInfo, "VPN authentication/session expired", ""},
	"vpn.authorization_denied":        {slog.LevelWarn, "VPN authorization refused", "reason"},
	"vpn.authorization_applied":       {slog.LevelInfo, "VPN authorization acknowledged by OpenVPN", ""},
	"controller.lease_expired":        {slog.LevelError, "Controller lease expired; stopping the OpenVPN pair", ""},
	"controller.ready":                {slog.LevelInfo, "Remote controller ready", ""},
	"controller.ack_expired":          {slog.LevelWarn, "Controller acknowledgement expired", ""},
	"controller.generation_rejected":  {slog.LevelError, "Controller rejected agent generation or operation", ""},
	"controller.request_retry":        {slog.LevelWarn, "Controller request retry", "operation status"},
	"controller.request_refused":      {slog.LevelWarn, "Controller request refused", "operation status"},
	"controller.decision_rejected":    {slog.LevelWarn, "Controller decision binding or validity rejected", ""},
	"session.unlimited_configured":    {slog.LevelWarn, "Unlimited VPN sessions configured; access may survive IdP user, group or MFA changes without a signed IdP session deadline", ""},
	"agent.https_ready":               {slog.LevelInfo, "HTTPS ready; waiting for OpenVPN management", ""},
	"agent.management_ready":          {slog.LevelInfo, "OpenVPN management ready", ""},
	"operator.tunnel_drop_requested":  {slog.LevelWarn, "Operator requested tunnel drop", ""},
	"operator.action_completed":       {slog.LevelInfo, "Node operator action completed", "action operator_request_id"},
	"maintenance.expired":             {slog.LevelError, "Node maintenance expired; operator action required", ""},
	"recovery.transition":             {slog.LevelInfo, "Node recovery phase changed", "phase reason"},
	"saml.response_refused":           {slog.LevelWarn, "SAML response refused", ""},
	"saml.login_started":              {slog.LevelInfo, "SAML browser login started", "purpose"},
	"saml.authorization_decided":      {slog.LevelInfo, "SAML authorization decision recorded", "purpose outcome reason"},
	"profile.issued":                  {slog.LevelInfo, "Client profile generated", ""},
	"profile.issue_failed":            {slog.LevelError, "Client profile generation failed", ""},
	"component.initialization_failed": {slog.LevelError, "Component initialization failed; check configuration, schema and privileges", ""},
	"component.stopped":               {slog.LevelError, "Component stopped unexpectedly", "reason"},
	"configuration.refused":           {slog.LevelError, "Configuration validation failed", ""},
	"operator.request_failed":         {slog.LevelError, "Local operator request failed", ""},
	"invocation.failed":               {slog.LevelError, "Lambda invocation failed", ""},
	"database.migration_failed":       {slog.LevelError, "Database migration failed; check configuration, schema and privileges", ""},
	"database.schema_current":         {slog.LevelInfo, "Database schema is current", ""},
	"profile.file_ready":              {slog.LevelInfo, "SupiVPN key/profile file ready", ""},
	"package.failed":                  {slog.LevelError, "Lambda packaging failed; check input files and architecture", ""},
	"manifest.failed":                 {slog.LevelError, "Release manifest failed; rebuild all artifacts", ""},
}

type Logger struct{ logger *slog.Logger }
type loggerKey struct{}
type requestKey struct{}

var current atomic.Pointer[Logger]

func init() { Configure("runtime") }

// Configure is called once by each executable before doing work. Dependencies
// retain their own logging; the process-global standard log logger is untouched.
func Configure(component string) { current.Store(New(os.Stderr, component)) }

func New(w io.Writer, component string) *Logger {
	if !oneOf(component, "runtime agent controller public agent_api recovery migrate profile package release_manifest") {
		component = "runtime"
	}
	h := slog.NewJSONHandler(escapedWriter{w}, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.TimeKey:
			return slog.Time("timestamp", a.Value.Time().UTC())
		case slog.MessageKey:
			a.Key = "message"
		}
		return a
	}})
	return &Logger{slog.New(h).With("schema_version", 1, "service", "supivpn", "component", component)}
}

// WithLogger supports dependency injection without replacing a global logger.
func WithLogger(ctx context.Context, logger *Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerKey{}, logger)
}

// WithRequestID accepts an invocation ID supplied by the platform adapter, never
// an HTTP header. It is correlation metadata, not authentication or a login token.
func WithRequestID(ctx context.Context, id string) context.Context {
	if !identifier(id, 128) {
		return ctx
	}
	return context.WithValue(ctx, requestKey{}, id)
}

func Emit(ctx context.Context, event string, attrs ...slog.Attr) {
	if ctx == nil {
		ctx = context.Background()
	}
	l, _ := ctx.Value(loggerKey{}).(*Logger)
	if l == nil {
		l = current.Load()
	}
	l.Emit(ctx, event, attrs...)
}

func (l *Logger) Emit(ctx context.Context, event string, attrs ...slog.Attr) {
	d, ok := events[event]
	if !ok {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	clean := []slog.Attr{slog.String("event", event)}
	if id := tracecontext.ID(ctx); tracecontext.ValidID(id) {
		clean = append(clean, slog.String("trace_id", id))
	}
	seen := make(map[string]bool)
	if id, ok := ctx.Value(requestKey{}).(string); ok && identifier(id, 128) {
		clean = append(clean, slog.String("request_id", id))
	}
	for _, a := range attrs {
		if seen[a.Key] || !(oneOf(a.Key, "node_id generation cid kid") || oneOf(a.Key, d.fields)) || !safe(a) {
			continue
		}
		seen[a.Key] = true
		clean = append(clean, a)
		if event == "recovery.transition" && a.Key == "phase" && a.Value.String() == "blocked" {
			d.level = slog.LevelError
		}
		if event == "saml.authorization_decided" && a.Key == "outcome" && a.Value.String() == "denied" {
			d.level = slog.LevelWarn
		}
	}
	l.logger.LogAttrs(ctx, d.level, d.message, clean...)
}

func oneOf(value, choices string) bool {
	for _, choice := range strings.Fields(choices) {
		if value == choice {
			return true
		}
	}
	return false
}

func identifier(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func safe(a slog.Attr) bool {
	// Never resolve LogValuer/Any values: even String/Error methods can leak data.
	switch a.Key {
	case "cid", "kid":
		return a.Value.Kind() == slog.KindUint64 || a.Value.Kind() == slog.KindInt64 && a.Value.Int64() >= 0
	case "status":
		return a.Value.Kind() == slog.KindInt64 && a.Value.Int64() >= 0 && a.Value.Int64() <= 599
	}
	if a.Value.Kind() != slog.KindString {
		return false
	}
	s := a.Value.String()
	switch a.Key {
	case "username":
		return len(s) <= 1024 && utf8.ValidString(s)
	case "node_id", "generation", "group_name", "operator_request_id":
		return identifier(s, 128)
	case "address":
		_, err := netip.ParseAddr(s)
		return err == nil
	case "operation":
		return oneOf(s, "register fetch ack cancel heartbeat")
	case "action":
		return oneOf(s, "maintenance-begin maintenance-end maintenance-renew maintenance-replace recovery-resume recovery-resolve")
	case "phase":
		return oneOf(s, "inspect stop start verify complete blocked")
	case "purpose":
		return oneOf(s, "vpn_connect profile_download")
	case "outcome":
		return oneOf(s, "allowed denied applied failed")
	case "reason":
		return oneOf(s, "capacity_or_missing_webauth connection_limit invalid_groups_claim no_vpn_group pool_full deadline stop_budget start_budget retired_stopped retired_running already_stopped fenced terminated start_disabled healthy observation_timeout management_unavailable listener_unavailable startup_failed")
	}
	return false
}

// Preserve exact decoded Unicode usernames while preventing bidi controls and
// Unicode line separators from visually spoofing raw JSON log viewers.
var escapeControls = strings.NewReplacer(
	"\u061c", `\u061c`, "\u200e", `\u200e`, "\u200f", `\u200f`,
	"\u2028", `\u2028`, "\u2029", `\u2029`, "\u202a", `\u202a`,
	"\u202b", `\u202b`, "\u202c", `\u202c`, "\u202d", `\u202d`, "\u202e", `\u202e`,
	"\u2066", `\u2066`, "\u2067", `\u2067`, "\u2068", `\u2068`, "\u2069", `\u2069`,
)

type escapedWriter struct{ io.Writer }

func (w escapedWriter) Write(p []byte) (int, error) {
	encoded := escapeControls.Replace(string(p))
	n, err := io.WriteString(w.Writer, encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
