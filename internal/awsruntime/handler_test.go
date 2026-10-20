// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestScheduledCleanupBoundary(t *testing.T) {
	prunes, calls := 0, 0
	h := RecoveryHandler(func(context.Context) error { prunes++; return nil }, "arn:example:rule", nil)
	http := HTTPHandler(func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		calls++
		return events.APIGatewayProxyResponse{StatusCode: 204}, nil
	})
	for _, raw := range []string{
		`{"source":"aws.events","detail-type":"Scheduled Event","resources":["wrong"]}`,
		`{"source":"aws.events","detail-type":"Scheduled Event","resources":["arn:example:rule"],"requestContext":{}}`,
		`{"source":"other","detail-type":"Scheduled Event","resources":["arn:example:rule"]}`,
	} {
		if _, err := h(context.Background(), json.RawMessage(raw)); err == nil {
			t.Fatal("untrusted cleanup accepted")
		}
	}
	if prunes != 0 || calls != 0 {
		t.Fatal("invalid event had effects")
	}
	if _, err := h(context.Background(), json.RawMessage(`{"source":"aws.events","detail-type":"Scheduled Event","resources":["arn:example:rule"]}`)); err != nil || prunes != 1 {
		t.Fatal("cleanup dispatch")
	}
	raw, _ := json.Marshal(events.APIGatewayProxyRequest{Body: `{"source":"aws.events"}`})
	if _, err := http(context.Background(), raw); err != nil || calls != 1 || prunes != 1 {
		t.Fatal("HTTP body influenced dispatch")
	}
}
