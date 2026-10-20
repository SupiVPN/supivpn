// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package lambdaruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"supivpn/internal/logging"
	"supivpn/internal/tracecontext"
)

func TestInvocationLoggingUsesPlatformContextOnly(t *testing.T) {
	var b bytes.Buffer
	ctx := logging.WithLogger(context.Background(), logging.New(&b, "recovery"))
	handler := withInvocation(func(ctx context.Context, payload string) (string, error) {
		logging.Emit(ctx, "maintenance.expired")
		return "unchanged", errors.New("secret-driver-error")
	})
	platform := lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{AwsRequestID: "platform-request-1"})
	result, err := handler(platform, "secret-payload")
	if result != "unchanged" || err == nil {
		t.Fatal("logging changed handler result")
	}
	if strings.Contains(b.String(), "secret") {
		t.Fatal("payload/raw error disclosed")
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 {
		t.Fatal("missing structured invocation logs")
	}
	var trace string
	for _, line := range lines {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil || row["request_id"] != "platform-request-1" {
			t.Fatal("missing platform correlation")
		}
		id, _ := row["trace_id"].(string)
		if !tracecontext.ValidID(id) || trace != "" && id != trace { t.Fatal("invocation trace lost") }
		trace = id
	}
	b.Reset()
	_, _ = handler(ctx, "secret-payload")
	if strings.Contains(b.String(), "request_id") {
		t.Fatal("warm invocation retained prior ID")
	}
	if strings.Contains(b.String(), trace) { t.Fatal("warm invocation reused prior trace") }
}
