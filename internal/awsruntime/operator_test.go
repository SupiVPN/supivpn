// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"supivpn/internal/operatorapi"
	"testing"
)

func TestOperatorDispatchCannotBeSelectedFromHTTP(t *testing.T) {
	calls := 0
	op := func(context.Context, json.RawMessage) (any, error) { calls++; return nil, nil }
	enabled := RecoveryHandler(func(context.Context) error { return nil }, "rule", op)
	disabled := RecoveryHandler(func(context.Context) error { return nil }, "rule", nil)
	direct := json.RawMessage(`{"source":"supivpn.operator.v1","action":"status","node_id":"node-a"}`)
	if _, e := disabled(context.Background(), direct); e == nil || calls != 0 {
		t.Fatal("disabled operator dispatched")
	}
	for _, event := range []events.APIGatewayProxyRequest{
		{HTTPMethod: "POST", Body: string(direct)},
		{HTTPMethod: "POST", Headers: map[string]string{"source": operatorapi.Source}},
		{HTTPMethod: "POST", QueryStringParameters: map[string]string{"source": operatorapi.Source}},
	} {
		raw, _ := json.Marshal(event)
		if _, e := enabled(context.Background(), raw); e == nil || calls != 0 {
			t.Fatal("HTTP selected operator handler")
		}
	}
	mixed := json.RawMessage(`{"source":"supivpn.operator.v1","requestContext":{},"action":"status","node_id":"node-a"}`)
	if _, e := enabled(context.Background(), mixed); e == nil || calls != 0 {
		t.Fatal("mixed proxy invocation selected operator")
	}
	if _, e := enabled(context.Background(), direct); e != nil || calls != 1 {
		t.Fatal("explicit direct invocation refused")
	}
}
