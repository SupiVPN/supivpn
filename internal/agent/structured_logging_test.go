// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"supivpn/internal/logging"
	"supivpn/internal/tracecontext"
)

func TestControllerLogsExcludeSAMLAndBrowserSecrets(t *testing.T) {
	signer, metadata := testIdP(t)
	for _, signed := range []bool{false, true} {
		a, commands := testApp(t, metadata)
		var b bytes.Buffer
		logger := logging.New(&b, "public")
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := logging.WithRequestID(logging.WithLogger(r.Context(), logger), "trusted-invocation")
			r.Header.Set("Authorization", "Bearer synthetic-sensitive-value")
			r.Header.Set("X-Request-ID", "attacker-request-id")
			r.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
			r.Header.Set("tracestate", "vendor=attacker")
			r.Header.Set("baggage", "username=attacker")
			a.handler().ServeHTTP(w, r.WithContext(ctx))
		})
		body := responseBody(t, a, signer, assertionFor(a), signed, false)
		reply := submitTo(wrapped, a, body, "test-browser")
		wantStatus, wantEvent := http.StatusForbidden, "saml.response_refused"
		if signed {
			wantStatus, wantEvent = http.StatusOK, "saml.authorization_decided"
			<-commands
		}
		if reply.Code != wantStatus {
			t.Fatal("logging changed SAML result")
		}
		var row map[string]any
		if json.Unmarshal(b.Bytes(), &row) != nil || row["event"] != wantEvent ||
			row["component"] != "public" || row["request_id"] != "trusted-invocation" {
			t.Fatal("structured SAML event missing")
		}
		if row["trace_id"] != tracecontext.ForLogin("test-ticket") {
			t.Fatal("SAML flow trace was not reconstructed from bound login")
		}
		for _, secret := range []string{"synthetic-sensitive-value", "attacker-request-id", "test-ticket", "test-browser", "test-user", "SAMLResponse", "RelayState", body} {
			if strings.Contains(b.String(), secret) {
				t.Fatal("SAML/request material leaked into log")
			}
		}
	}
}

func TestUnboundBrowserFailureCannotSpoofSessionTrace(t *testing.T) {
	_, metadata := testIdP(t)
	a, _ := testApp(t, metadata)
	var b bytes.Buffer
	logger := logging.New(&b, "public")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
		a.handler().ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), logger)))
	})
	res := submitTo(h, a, "invalid", "wrong-browser")
	if res.Code < 400 {
		t.Fatal("invalid callback accepted")
	}
	var row map[string]any
	if json.Unmarshal(b.Bytes(), &row) != nil {
		t.Fatal("missing refusal log")
	}
	id, _ := row["trace_id"].(string)
	if !tracecontext.ValidID(id) || id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || id == tracecontext.ForLogin("test-ticket") {
		t.Fatal("unbound request joined a session trace")
	}
}
