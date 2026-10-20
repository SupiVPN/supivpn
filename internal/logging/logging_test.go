// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"supivpn/internal/tracecontext"
)

func decode(t *testing.T, data string) map[string]any {
	t.Helper()
	if strings.Count(data, "\n") != 1 {
		t.Fatal("expected one physical log line")
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestJSONSchemaAndUnicodeInjection(t *testing.T) {
	var b bytes.Buffer
	username := "alice\"\nforged\t\u202e\u2066\u042f"
	New(&b, "agent").Emit(context.Background(), "vpn.tunnel_established",
		slog.Uint64("cid", 0), slog.String("username", username),
		slog.String("group_name", "admins-vpn"), slog.String("address", "10.203.0.2"))
	got := decode(t, b.String())
	if got["schema_version"] != float64(1) || got["service"] != "supivpn" || got["component"] != "agent" ||
		got["level"] != "INFO" || got["event"] != "vpn.tunnel_established" || got["username"] != username || got["cid"] != float64(0) {
		t.Fatal("JSON schema/decoded identity mismatch")
	}
	stamp, err := time.Parse(time.RFC3339Nano, got["timestamp"].(string))
	if err != nil || stamp.Location() != time.UTC {
		t.Fatal("timestamp must be RFC3339 in UTC")
	}
	if strings.ContainsAny(b.String(), "\u202e\u2066") {
		t.Fatal("unescaped bidi controls in raw log")
	}
}

type explosiveValue struct{}

func (explosiveValue) LogValue() slog.Value { panic("must not resolve arbitrary values") }
func (explosiveValue) String() string       { panic("must not stringify arbitrary values") }

func TestSensitiveUnknownAndSpoofedFieldsAreDropped(t *testing.T) {
	var b bytes.Buffer
	logger := New(&b, "public")
	ctx := tracecontext.WithID(WithRequestID(context.Background(), "invocation-1"), "0123456789abcdef0123456789abcdef")
	logger.Emit(ctx, "saml.response_refused",
		slog.String("SAMLResponse", "secret-assertion"), slog.String("cookie", "secret-cookie"),
		slog.String("ticket", "secret-ticket"), slog.String("url", "https://secret.invalid/login/secret"),
		slog.String("error", "secret-dsn"), slog.String("username", "unverified-user"),
		slog.String("component", "forged"), slog.String("level", "INFO"), slog.String("message", "forged"),
		slog.String("request_id", "forged"), slog.Any("node_id", explosiveValue{}),
		slog.String("trace_id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), slog.String("span_id", "forged-span"),
		slog.Group("node_id", "secret", "secret-value"), slog.String("generation", "bad\nvalue"))
	got := decode(t, b.String())
	if got["level"] != "WARN" || got["component"] != "public" || got["request_id"] != "invocation-1" {
		t.Fatal("metadata spoofed")
	}
	if got["trace_id"] != tracecontext.ID(ctx) || strings.Count(b.String(), "\"trace_id\"") != 1 {
		t.Fatal("trace context spoofed")
	}
	for _, banned := range []string{"secret", "forged", "unverified-user", "bad", "node_id", "generation"} {
		if strings.Contains(b.String(), banned) {
			t.Fatalf("disallowed field leaked: %s", banned)
		}
	}
	b.Reset()
	logger.Emit(ctx, "secret-unknown-event")
	if b.Len() != 0 {
		t.Fatal("arbitrary event text logged")
	}
}

func TestFieldValidationAndDuplicateKeys(t *testing.T) {
	var b bytes.Buffer
	logger := New(&b, "agent")
	logger.Emit(context.Background(), "vpn.tunnel_established",
		slog.Uint64("cid", 2), slog.Uint64("cid", 3), slog.String("kid", "wrong-type"),
		slog.String("username", strings.Repeat("x", 1025)), slog.String("address", "not-an-ip"),
		slog.Any("group_name", errors.New("sensitive")))
	got := decode(t, b.String())
	if got["cid"] != float64(2) || strings.Count(b.String(), "\"cid\"") != 1 {
		t.Fatal("duplicate key ambiguity")
	}
	for _, key := range []string{"kid", "username", "address", "group_name"} {
		if _, ok := got[key]; ok {
			t.Fatal("invalid field accepted")
		}
	}
}

func TestRecoveryAndAuthorizationSeverity(t *testing.T) {
	for _, tc := range []struct{ event, key, value, level string }{
		{"recovery.transition", "phase", "blocked", "ERROR"},
		{"recovery.transition", "phase", "complete", "INFO"},
		{"saml.authorization_decided", "outcome", "denied", "WARN"},
		{"maintenance.expired", "", "", "ERROR"},
		{"controller.lease_expired", "", "", "ERROR"},
	} {
		var b bytes.Buffer
		New(&b, "recovery").Emit(context.Background(), tc.event, slog.String(tc.key, tc.value))
		if decode(t, b.String())["level"] != tc.level {
			t.Fatal("unsafe severity", tc.event)
		}
	}
}

func TestConcurrentContextsDoNotLeakRequestIDs(t *testing.T) {
	var b bytes.Buffer
	logger := New(&b, "public")
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := WithLogger(WithRequestID(context.Background(), fmt.Sprintf("request-%d", i)), logger)
			ctx = tracecontext.WithID(ctx, tracecontext.ForLogin(fmt.Sprintf("synthetic-ticket-%d", i)))
			Emit(ctx, "vpn.disconnected", slog.Int("cid", i))
		}(i)
	}
	wg.Wait()
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		entry := decode(t, line+"\n")
		if entry["request_id"] != fmt.Sprintf("request-%d", int(entry["cid"].(float64))) {
			t.Fatal("request context leaked")
		}
		if entry["trace_id"] != tracecontext.ForLogin(fmt.Sprintf("synthetic-ticket-%d", int(entry["cid"].(float64)))) {
			t.Fatal("trace context leaked")
		}
	}
	if strings.Count(b.String(), "\n") != 100 {
		t.Fatal("concurrent lines lost or interleaved")
	}
	b.Reset()
	Emit(WithLogger(context.Background(), logger), "saml.response_refused")
	if _, ok := decode(t, b.String())["request_id"]; ok {
		t.Fatal("previous request ID retained")
	}
	if _, ok := decode(t, b.String())["trace_id"]; ok {
		t.Fatal("previous trace ID retained")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestLoggingFailureDoesNotPanicOrAlterControlFlow(t *testing.T) {
	New(brokenWriter{}, "agent").Emit(context.Background(), "controller.lease_expired")
}
