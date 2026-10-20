// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"testing"
)

func TestSecurityIsolatedLambdaDispatch(t *testing.T) {
	httpCalls, ticks, ops := 0, 0, 0
	http := HTTPHandler(func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		httpCalls++
		return events.APIGatewayProxyResponse{StatusCode: 204}, nil
	})
	recovery := RecoveryHandler(func(context.Context) error { ticks++; return nil }, "arn:test:rule", func(context.Context, json.RawMessage) (any, error) { ops++; return nil, nil })
	scheduled := json.RawMessage(`{"source":"aws.events","detail-type":"Scheduled Event","resources":["arn:test:rule"]}`)
	operator := json.RawMessage(`{"source":"supivpn.operator.v1","action":"status"}`)
	for _, raw := range []json.RawMessage{scheduled, operator, json.RawMessage(`{"source":null,"requestContext":{}}`)} {
		if _, err := http(context.Background(), raw); err == nil {
			t.Fatal("HTTP accepted administrative envelope")
		}
	}
	proxy, _ := json.Marshal(events.APIGatewayProxyRequest{Body: string(operator)})
	if _, err := http(context.Background(), proxy); err != nil || httpCalls != 1 {
		t.Fatal("body altered HTTP routing")
	}
	if _, err := recovery(context.Background(), proxy); err == nil || ticks != 0 || ops != 0 {
		t.Fatal("recovery accepted HTTP")
	}
	if _, err := recovery(context.Background(), scheduled); err != nil || ticks != 1 {
		t.Fatal("schedule unavailable")
	}
	if _, err := recovery(context.Background(), operator); err != nil || ops != 1 {
		t.Fatal("operator unavailable")
	}
	for _, raw := range []string{`{"source":"aws.events","detail-type":"Scheduled Event","resources":["wrong"]}`, `{"source":"aws.events","detail-type":"Scheduled Event","resources":["arn:test:rule"],"requestContext":{}}`} {
		if _, err := recovery(context.Background(), json.RawMessage(raw)); err == nil {
			t.Fatal("untrusted schedule accepted")
		}
	}
	if ticks != 1 || ops != 1 {
		t.Fatal("invalid event had side effects")
	}
	for _, suffix := range []string{`,"source":"aws.events"}`, `,"action":"status"}`, `,"requestContext":null}`, `} {}`} {
		raw := append(append(json.RawMessage{}, scheduled[:len(scheduled)-1]...), suffix...)
		if _, err := recovery(context.Background(), raw); err == nil {
			t.Fatal("ambiguous schedule accepted")
		}
	}
	if ticks != 1 || ops != 1 {
		t.Fatal("ambiguous event caused side effects")
	}
}
